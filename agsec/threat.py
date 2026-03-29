"""Threat analysis engine — classifies observed agent actions by consequence."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ThreatPattern:
    id: str
    name: str
    severity: Severity
    action_types: List[str]
    param_field: str  # which param to check ("command", "file_path", "url", or "" for match-all)
    regex: str  # regex to match against param value ("" = match any)
    consequence: str
    recommendation: str


@dataclass
class ThreatFinding:
    pattern: ThreatPattern
    matched_value: str
    policy_status: str  # "allow", "block", "review"


@dataclass
class ThreatReport:
    threats: List[ThreatFinding]  # allowed/review — real threats
    blocked: List[ThreatFinding]  # blocked by policy — caught
    blast_radius: float  # 0.0 - 10.0, only from threats
    blast_radius_label: str
    severity_counts: Dict[str, int]  # only from threats
    blocked_counts: Dict[str, int]  # from blocked
    total_executions: int
    recommendations: List[str]


# ---------------------------------------------------------------------------
# Pattern registry — regexes reused from policy templates
# ---------------------------------------------------------------------------

THREAT_PATTERNS: List[ThreatPattern] = [
    # CRITICAL
    ThreatPattern(
        id="read_secrets",
        name="Reading secret files",
        severity=Severity.CRITICAL,
        action_types=["file.read"],
        param_field="file_path",
        regex=r"(\.env$|\.env\..+|credentials\.json|secrets\.ya?ml|\.ssh/|id_rsa|\.aws/credentials|\.gcloud/|service[_-]account.*\.json)",
        consequence=(
            "Secrets exposed to agent context \u2014 API keys, credentials, or private keys "
            "readable by the agent and potentially exfiltrated in subsequent actions"
        ),
        recommendation="Add a deny rule for file.read on sensitive file patterns",
    ),
    ThreatPattern(
        id="secret_access",
        name="Secret access via bash",
        severity=Severity.CRITICAL,
        action_types=["bash.execute"],
        param_field="command",
        regex=r"(cat|less|more|head|tail)\s+.*(\.env|credentials|secrets|password|private_key|id_rsa)",
        consequence=(
            "Secrets exposed to agent context \u2014 API keys, credentials, or private keys "
            "readable by the agent and potentially exfiltrated in subsequent actions"
        ),
        recommendation="Ensure BlockSecretAccess policy (02_bash.yaml) is enforced",
    ),
    ThreatPattern(
        id="data_exfiltration",
        name="Data exfiltration",
        severity=Severity.CRITICAL,
        action_types=["bash.execute"],
        param_field="command",
        regex=r"(curl|wget|nc|ncat).*(-d|--data|--upload|-T).*(\.env|credentials|secret|password|token)",
        consequence=(
            "Sensitive data actively sent to an external endpoint \u2014 "
            "credentials or tokens leaving your environment"
        ),
        recommendation="Ensure BlockDataExfiltration policy (02_bash.yaml) is enforced",
    ),
    ThreatPattern(
        id="destructive_sql",
        name="Destructive SQL (DDL)",
        severity=Severity.CRITICAL,
        action_types=["bash.execute"],
        param_field="command",
        regex=r"(?i)(DROP\s+(TABLE|DATABASE)|TRUNCATE\s+TABLE|ALTER\s+TABLE\s+\S+\s+DROP)",
        consequence=(
            "Irreversible database destruction \u2014 tables or entire databases "
            "dropped with no recovery without backups"
        ),
        recommendation="Ensure BlockDestructiveSQL policy (02_bash.yaml) is enforced",
    ),
    ThreatPattern(
        id="dml_sql",
        name="Data modification SQL (DML)",
        severity=Severity.HIGH,
        action_types=["bash.execute"],
        param_field="command",
        regex=r"(?i)(DELETE\s+FROM|UPDATE\s+\S+\s+SET|INSERT\s+INTO|MERGE\s+INTO)",
        consequence=(
            "Direct database modification via SQL \u2014 data corruption, "
            "unauthorized changes, or audit trail manipulation"
        ),
        recommendation="Review raw SQL commands — use application layer for data changes",
    ),
    ThreatPattern(
        id="audit_tampering",
        name="Audit database access",
        severity=Severity.CRITICAL,
        action_types=["bash.execute"],
        param_field="command",
        regex=r"(sqlite3|psql|mysql|mongosh?)\s+.*(\\.agsec/|audit\.db)",
        consequence=(
            "Direct access to audit database \u2014 attacker could read, modify, "
            "or wipe the audit trail to cover tracks"
        ),
        recommendation="URGENT: Agent accessed audit database directly \u2014 investigate immediately",
    ),
    # HIGH
    ThreatPattern(
        id="file_deletion",
        name="File deletion",
        severity=Severity.HIGH,
        action_types=["bash.execute"],
        param_field="command",
        regex=r"\brm\s",
        consequence=(
            "Permanent file loss \u2014 deleted files cannot be recovered "
            "without version control or backups"
        ),
        recommendation="Ensure BlockFileDelete policy (02_bash.yaml) is enforced",
    ),
    ThreatPattern(
        id="destructive_fs",
        name="Destructive filesystem operation",
        severity=Severity.HIGH,
        action_types=["bash.execute"],
        param_field="command",
        regex=r"(chmod\s+777|mkfs\.|dd\s+if=|shred\s|wipe\s)",
        consequence=(
            "Destructive filesystem operation \u2014 chmod 777 exposes files to all users, "
            "dd/shred destroys data at block level"
        ),
        recommendation="Ensure BlockDestructiveFS policy (02_bash.yaml) is enforced",
    ),
    ThreatPattern(
        id="read_system",
        name="Reading system files",
        severity=Severity.HIGH,
        action_types=["file.read"],
        param_field="file_path",
        regex=r"^/(etc|proc|sys|boot|root)/",
        consequence=(
            "System file contents exposed \u2014 /etc/passwd, /etc/shadow, or process info "
            "leaking to agent context"
        ),
        recommendation="Add a deny rule for file.read on system directories",
    ),
    ThreatPattern(
        id="read_policy",
        name="Reading policy/guardrail config",
        severity=Severity.HIGH,
        action_types=["file.read"],
        param_field="file_path",
        regex=r"(\.agsec\.yaml|policies/.*\.ya?ml|\.claude/settings.*\.json|\.codex/hooks\.json)",
        consequence=(
            "Agent reading its own guardrails \u2014 could learn what's blocked "
            "and craft bypass strategies"
        ),
        recommendation="Add a deny rule for file.read on policy and hook config files",
    ),
    ThreatPattern(
        id="notebook_sensitive",
        name="Notebook edit of sensitive file",
        severity=Severity.HIGH,
        action_types=["notebook.edit"],
        param_field="file_path",
        regex=r"(\.env$|\.env\..+|credentials\.json|secrets\.ya?ml|\.ssh/|id_rsa|\.aws/credentials)",
        consequence=(
            "Credential tampering via notebook \u2014 same risk as direct file.write "
            "to sensitive files"
        ),
        recommendation="Add notebook.edit to the BlockWriteSensitive policy in 03_files.yaml",
    ),
    ThreatPattern(
        id="write_sensitive",
        name="Write to sensitive files",
        severity=Severity.HIGH,
        action_types=["file.write", "file.edit"],
        param_field="file_path",
        regex=r"(\.env$|\.env\..+|credentials\.json|secrets\.ya?ml|\.ssh/|id_rsa|\.aws/credentials|\.gcloud/|service[_-]account.*\.json)",
        consequence=(
            "Credential tampering \u2014 agent modifying .env, SSH keys, or cloud credentials "
            "could escalate its own privileges or break authentication"
        ),
        recommendation="Ensure BlockWriteSensitive policy (03_files.yaml) is enforced",
    ),
    ThreatPattern(
        id="write_system",
        name="Write to system directories",
        severity=Severity.HIGH,
        action_types=["file.write", "file.edit"],
        param_field="file_path",
        regex=r"^/(etc|usr|var|sys|proc|boot|root)/",
        consequence=(
            "System-level modification \u2014 changes to /etc, /usr could break "
            "OS services or create persistent backdoors"
        ),
        recommendation="Ensure BlockWriteSystemDirs policy (03_files.yaml) is enforced",
    ),
    ThreatPattern(
        id="policy_tampering",
        name="Policy tampering",
        severity=Severity.HIGH,
        action_types=["file.write", "file.edit"],
        param_field="file_path",
        regex=r"(\.agsec\.yaml|policies/.*\.ya?ml|\.claude/settings.*\.json|\.codex/hooks\.json)",
        consequence=(
            "Policy escape \u2014 agent modifying its own guardrails "
            "could disable all protections"
        ),
        recommendation="URGENT: Agent attempted to modify its own guardrails \u2014 investigate immediately",
    ),
    ThreatPattern(
        id="force_push",
        name="Force push",
        severity=Severity.HIGH,
        action_types=["bash.execute"],
        param_field="command",
        regex=r"git\s+push\s+.*(-f|--force)",
        consequence=(
            "Git history rewritten \u2014 team members lose commits, "
            "CI/CD pipelines may break, code review bypassed"
        ),
        recommendation="Ensure BlockForcePush policy (05_git.yaml) is enforced",
    ),
    ThreatPattern(
        id="destructive_git",
        name="Destructive git operation",
        severity=Severity.HIGH,
        action_types=["bash.execute"],
        param_field="command",
        regex=r"git\s+(reset\s+--hard|clean\s+-[a-zA-Z]*f)",
        consequence=(
            "Local changes permanently destroyed \u2014 "
            "uncommitted work and untracked files gone"
        ),
        recommendation="Ensure BlockDestructiveGit policy (05_git.yaml) is enforced",
    ),
    # MEDIUM
    ThreatPattern(
        id="push_protected",
        name="Push to protected branch",
        severity=Severity.MEDIUM,
        action_types=["bash.execute"],
        param_field="command",
        regex=r"git\s+push\s+.*\s+(main|master|production|release)\b",
        consequence=(
            "Unreviewed code pushed directly to production branch \u2014 "
            "bypasses PR review and CI checks"
        ),
        recommendation="Ensure BlockPushProtected policy (05_git.yaml) is enforced",
    ),
    ThreatPattern(
        id="scan_secrets",
        name="Scanning for secrets",
        severity=Severity.MEDIUM,
        action_types=["file.glob", "file.grep"],
        param_field="pattern",
        regex=r"(\.env|credentials|secret|password|private_key|id_rsa|\.aws|\.ssh|token)",
        consequence=(
            "Agent actively searching for secret files \u2014 "
            "reconnaissance step before exfiltration"
        ),
        recommendation="Monitor file.glob and file.grep patterns for sensitive keywords",
    ),
    ThreatPattern(
        id="external_fetch",
        name="External web fetch",
        severity=Severity.MEDIUM,
        action_types=["web.fetch"],
        param_field="url",
        regex=r"^https?://(?!localhost|127\.0\.0\.1|\[::1\])",
        consequence=(
            "Data sent to or fetched from external endpoint \u2014 "
            "risk of SSRF or unintended data leakage"
        ),
        recommendation="Review external web fetch policy (04_web.yaml)",
    ),
    # LOW
    ThreatPattern(
        id="agent_spawn",
        name="Sub-agent spawned",
        severity=Severity.LOW,
        action_types=["agent.spawn"],
        param_field="",
        regex="",
        consequence=(
            "Sub-agent spawned \u2014 expands attack surface, "
            "child agent inherits parent's permissions"
        ),
        recommendation="Review agent.spawn permissions if sub-agents are not expected",
    ),
]


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


class ThreatClassifier:
    """Classify audit executions into threat findings with consequences."""

    def __init__(self) -> None:
        self.patterns = THREAT_PATTERNS

    def classify(self, executions: List[Dict[str, Any]]) -> ThreatReport:
        threats: List[ThreatFinding] = []
        blocked: List[ThreatFinding] = []

        for row in executions:
            action = row.get("action", "")
            policy_status = row.get("policy_status", "allow")
            outcome = row.get("outcome")  # "allowed", "blocked", "review", or None (legacy)

            # Parse params
            raw_params = row.get("params", "{}")
            if isinstance(raw_params, str):
                try:
                    params = json.loads(raw_params)
                except (json.JSONDecodeError, TypeError):
                    params = {}
            elif isinstance(raw_params, dict):
                params = raw_params
            else:
                params = {}

            for pattern in self.patterns:
                if not self._action_matches(action, pattern.action_types):
                    continue

                matched_value = self._extract_and_match(params, pattern)
                if matched_value is None:
                    continue

                finding = ThreatFinding(
                    pattern=pattern,
                    matched_value=matched_value,
                    policy_status=policy_status,
                )

                # Use outcome if available (new logs), fall back to policy_status (legacy)
                if outcome:
                    actually_blocked = outcome == "blocked"
                else:
                    # Legacy rows: no outcome column, use policy_status
                    actually_blocked = policy_status == "block"

                if actually_blocked:
                    blocked.append(finding)
                else:
                    # "allowed" and "review" = action got through = threat
                    threats.append(finding)

        # Calculate blast radius from threats only
        severity_counts = self._count_by_severity(threats)
        blocked_counts = self._count_by_severity(blocked)
        blast_radius = self._calculate_blast_radius(severity_counts)
        blast_radius_label = self._label_blast_radius(blast_radius)

        recommendations = self._generate_recommendations(
            threats, blocked, severity_counts
        )

        return ThreatReport(
            threats=threats,
            blocked=blocked,
            blast_radius=blast_radius,
            blast_radius_label=blast_radius_label,
            severity_counts=severity_counts,
            blocked_counts=blocked_counts,
            total_executions=len(executions),
            recommendations=recommendations,
        )

    def _action_matches(self, action: str, action_types: List[str]) -> bool:
        return action in action_types

    def _extract_and_match(
        self, params: Dict[str, Any], pattern: ThreatPattern
    ) -> Optional[str]:
        """Extract param value and match against pattern regex. Returns matched value or None."""
        if not pattern.param_field:
            # Match-all pattern (e.g., agent_spawn)
            return "(action matched)"

        value = params.get(pattern.param_field, "")
        if not isinstance(value, str):
            value = str(value)

        if not value:
            return None

        if not pattern.regex:
            return value

        try:
            if re.search(pattern.regex, value):
                # Truncate for display
                return value[:120] if len(value) > 120 else value
        except re.error:
            pass

        return None

    def _count_by_severity(
        self, findings: List[ThreatFinding]
    ) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f.pattern.severity.value] += 1
        return counts

    def _calculate_blast_radius(self, severity_counts: Dict[str, int]) -> float:
        raw = (
            severity_counts.get("critical", 0) * 4
            + severity_counts.get("high", 0) * 2
            + severity_counts.get("medium", 0) * 1
            + severity_counts.get("low", 0) * 0.25
        )
        return min(10.0, round(raw, 1))

    def _label_blast_radius(self, score: float) -> str:
        if score == 0:
            return "None"
        if score <= 2.0:
            return "Low"
        if score <= 5.0:
            return "Moderate"
        if score <= 8.0:
            return "High"
        return "Critical"

    def _generate_recommendations(
        self,
        threats: List[ThreatFinding],
        blocked: List[ThreatFinding],
        severity_counts: Dict[str, int],
    ) -> List[str]:
        recs: List[str] = []
        seen_recs: set = set()

        has_critical_or_high = (
            severity_counts.get("critical", 0) > 0
            or severity_counts.get("high", 0) > 0
        )

        # Top-level urgency
        if has_critical_or_high:
            recs.append("Run `agsec enforce` to start blocking these actions")

        # Policy tampering gets special treatment
        for f in threats:
            if f.pattern.id == "policy_tampering":
                rec = "URGENT: Agent attempted to modify its own guardrails \u2014 investigate immediately"
                if rec not in seen_recs:
                    recs.insert(0, rec)
                    seen_recs.add(rec)
                break

        # Per-pattern recommendations (deduplicated)
        for f in threats:
            rec = f.pattern.recommendation
            if rec not in seen_recs:
                recs.append(rec)
                seen_recs.add(rec)

        # Positive reinforcement if policies are catching things
        if blocked and not threats:
            recs.append(
                "Your policies are working \u2014 all dangerous actions were blocked"
            )
        elif blocked:
            total_blocked = len(blocked)
            recs.append(
                f"Your policies caught {total_blocked} dangerous action{'s' if total_blocked != 1 else ''} \u2014 enforcement is working"
            )

        return recs


def group_findings(
    findings: List[ThreatFinding],
) -> List[Dict[str, Any]]:
    """Group findings by pattern ID for display. Returns list of grouped findings."""
    groups: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        pid = f.pattern.id
        if pid not in groups:
            groups[pid] = {
                "id": pid,
                "name": f.pattern.name,
                "severity": f.pattern.severity.value,
                "consequence": f.pattern.consequence,
                "count": 0,
                "examples": [],
            }
        groups[pid]["count"] += 1
        # Keep up to 3 examples
        if len(groups[pid]["examples"]) < 3:
            val = f.matched_value
            if val and val not in groups[pid]["examples"]:
                groups[pid]["examples"].append(val)

    # Sort by severity order
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    result = sorted(
        groups.values(), key=lambda g: severity_order.get(g["severity"], 99)
    )
    return result
