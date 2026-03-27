from __future__ import annotations

from typing import Any, Callable, Dict

from .exceptions import ActionNotFoundError

ActionFunc = Callable[..., Any]


class ActionRegistry:
    def __init__(self):
        self._actions: Dict[str, ActionFunc] = {}

    def register(self, name: str, func: ActionFunc) -> ActionFunc:
        if name in self._actions:
            raise ValueError(f"Action '{name}' is already registered")
        self._actions[name] = func
        return func

    def get(self, name: str) -> ActionFunc:
        if name not in self._actions:
            raise ActionNotFoundError(f"Action '{name}' not registered")
        return self._actions[name]

    def list_actions(self) -> Dict[str, ActionFunc]:
        return dict(self._actions)
