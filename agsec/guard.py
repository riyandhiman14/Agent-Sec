"""Generic @guard decorator for any Python function.

Usage:
    from agsec import guard

    @guard("email.send")
    def send_email(to, subject, body):
        ...

    @guard("payment.charge", agent="payment-agent")
    async def charge(amount, recipient):
        ...
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Callable, Optional

from .integrations._base import PolicyChecker


def guard(
    action: str,
    agent: Optional[str] = None,
    policy_dir: Optional[str] = None,
    audit: bool = True,
) -> Callable:
    """Decorator that enforces agsec policies on a function.

    Args:
        action: Action name for policy matching (e.g., "email.send", "payment.charge")
        agent: Agent name for agent-specific policy overlay
        policy_dir: Override policy directory
        audit: Enable audit logging

    Raises:
        PolicyViolationError: If the action is blocked or requires review

    Example:
        @guard("email.send")
        def send_email(to, subject, body):
            ...

        @guard("payment.charge", agent="billing-agent")
        async def charge(amount, recipient):
            ...
    """
    checker = PolicyChecker(policy_dir=policy_dir, agent=agent, audit=audit)

    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                # Build params from function signature
                params = _extract_params(func, args, kwargs)
                await checker.acheck_or_raise(action, params)
                return await func(*args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                params = _extract_params(func, args, kwargs)
                checker.check_or_raise(action, params)
                return func(*args, **kwargs)
            return sync_wrapper

    return decorator


def _extract_params(func: Callable, args: tuple, kwargs: dict) -> dict:
    """Extract function arguments as a flat dict for policy evaluation."""
    sig = inspect.signature(func)
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()
    return dict(bound.arguments)
