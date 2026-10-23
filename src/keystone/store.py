"""In-memory persistence.

Deliberately a plain dict behind a small interface: the interesting behaviour in
this project is the HTTP surface, and a real database would only add setup noise.
Swapping this for SQLAlchemy means reimplementing the same six methods.
"""
from __future__ import annotations

import itertools
import threading
import time
from dataclasses import dataclass, field
from typing import Any

ROLES = ("viewer", "editor", "admin")


@dataclass
class User:
    id: str
    email: str
    password_hash: str
    role: str = "viewer"
    created_at: float = field(default_factory=time.time)

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at,
        }


@dataclass
class Item:
    id: str
    owner_id: str
    name: str
    price_cents: int
    description: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "owner_id": self.owner_id,
            "name": self.name,
            "price_cents": self.price_cents,
            "description": self.description,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class Store:
    """Thread-safe collection of users and items."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._users: dict[str, User] = {}
        self._by_email: dict[str, str] = {}
        self._items: dict[str, Item] = {}
        self._ids = itertools.count(1)

    def _next_id(self, prefix: str) -> str:
        return f"{prefix}_{next(self._ids):06d}"

    # -- users ---------------------------------------------------------------
    def create_user(self, email: str, password_hash: str, role: str = "viewer") -> User:
        with self._lock:
            key = email.strip().lower()
            if key in self._by_email:
                raise ValueError("email already registered")
            if role not in ROLES:
                raise ValueError(f"unknown role {role!r}")
            user = User(id=self._next_id("usr"), email=key, password_hash=password_hash, role=role)
            self._users[user.id] = user
            self._by_email[key] = user.id
            return user

    def user_by_email(self, email: str) -> User | None:
        with self._lock:
            uid = self._by_email.get(email.strip().lower())
            return self._users.get(uid) if uid else None

    def user_by_id(self, user_id: str) -> User | None:
        with self._lock:
            return self._users.get(user_id)

    def count_users(self) -> int:
        with self._lock:
            return len(self._users)

    def set_role(self, user_id: str, role: str) -> User:
        with self._lock:
            if role not in ROLES:
                raise ValueError(f"unknown role {role!r}")
            user = self._users[user_id]
            user.role = role
            return user

    # -- items ---------------------------------------------------------------
    def create_item(self, owner_id: str, name: str, price_cents: int, description: str = "") -> Item:
        with self._lock:
            item = Item(
                id=self._next_id("itm"),
                owner_id=owner_id,
                name=name,
                price_cents=price_cents,
                description=description,
            )
            self._items[item.id] = item
            return item

    def get_item(self, item_id: str) -> Item | None:
        with self._lock:
            return self._items.get(item_id)

    def update_item(self, item_id: str, **changes: Any) -> Item:
        with self._lock:
            item = self._items[item_id]
            for key, value in changes.items():
                if value is not None:
                    setattr(item, key, value)
            item.updated_at = time.time()
            return item

    def delete_item(self, item_id: str) -> bool:
        with self._lock:
            return self._items.pop(item_id, None) is not None

    def list_items(
        self,
        *,
        owner_id: str | None = None,
        after: str | None = None,
        limit: int = 20,
    ) -> tuple[list[Item], str | None]:
        """Return a page of items plus the cursor for the next page.

        Sorted by id, which is monotonic, so a cursor is just the last id seen.
        """
        with self._lock:
            rows = sorted(self._items.values(), key=lambda i: i.id)
        if owner_id is not None:
            rows = [r for r in rows if r.owner_id == owner_id]
        if after is not None:
            rows = [r for r in rows if r.id > after]
        page = rows[:limit]
        next_cursor = page[-1].id if len(rows) > limit and page else None
        return page, next_cursor

    def clear(self) -> None:
        with self._lock:
            self._users.clear()
            self._by_email.clear()
            self._items.clear()
            self._ids = itertools.count(1)
