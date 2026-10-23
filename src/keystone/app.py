"""HTTP surface: routes, authorisation dependencies and middleware."""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, EmailStr, Field

from .config import settings
from .ratelimit import RateLimiter
from .security import TokenError, decode_token, encode_token, hash_password, verify_password
from .store import ROLES, Store, User

store = Store()
limiter = RateLimiter(settings.rate_limit, settings.rate_window)

app = FastAPI(
    title="Keystone API",
    version="1.0.0",
    description="JWT auth, role-based access control, rate limiting and cursor pagination.",
)


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=256)
    role: str = "viewer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class ItemCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    price_cents: int = Field(ge=0, le=100_000_000)
    description: str = Field(default="", max_length=2000)


class ItemUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    price_cents: int | None = Field(default=None, ge=0, le=100_000_000)
    description: str | None = Field(default=None, max_length=2000)


class ItemPage(BaseModel):
    items: list[dict[str, Any]]
    next_cursor: str | None
    count: int


# --------------------------------------------------------------------------- #
# Middleware
# --------------------------------------------------------------------------- #
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path in {"/health", "/docs", "/openapi.json", "/redoc"}:
        return await call_next(request)
    identity = request.headers.get("authorization") or (request.client.host if request.client else "anon")
    allowed, retry_after = limiter.check(identity)
    if not allowed:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "rate limit exceeded"},
            headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
        )
    return await call_next(request)


# --------------------------------------------------------------------------- #
# Dependencies
# --------------------------------------------------------------------------- #
def current_user(authorization: Annotated[str | None, Header()] = None) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        claims = decode_token(token, settings.secret)
    except TokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    user = store.user_by_id(str(claims.get("sub", "")))
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token subject no longer exists")
    return user


def require_roles(*allowed: str):
    """Build a dependency that admits only the listed roles."""

    def dependency(user: Annotated[User, Depends(current_user)]) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"role {user.role!r} may not perform this action",
            )
        return user

    return dependency


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/health", tags=["meta"])
def health() -> dict[str, Any]:
    return {"status": "ok", "users": store.count_users()}


@app.post("/auth/register", response_model=TokenResponse, status_code=201, tags=["auth"])
def register(body: RegisterRequest) -> TokenResponse:
    # The very first account bootstraps the system as an admin.
    role = "admin" if store.count_users() == 0 else body.role
    if role not in ROLES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown role {role!r}")
    try:
        user = store.create_user(body.email, hash_password(body.password), role)
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    token = encode_token({"sub": user.id, "role": user.role}, settings.secret, ttl_seconds=settings.token_ttl)
    return TokenResponse(access_token=token, expires_in=settings.token_ttl)


@app.post("/auth/login", response_model=TokenResponse, tags=["auth"])
def login(body: LoginRequest) -> TokenResponse:
    user = store.user_by_email(body.email)
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    token = encode_token({"sub": user.id, "role": user.role}, settings.secret, ttl_seconds=settings.token_ttl)
    return TokenResponse(access_token=token, expires_in=settings.token_ttl)


@app.get("/auth/me", tags=["auth"])
def me(user: Annotated[User, Depends(current_user)]) -> dict[str, Any]:
    return user.public()


@app.get("/items", response_model=ItemPage, tags=["items"])
def list_items(
    user: Annotated[User, Depends(current_user)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    cursor: str | None = None,
    mine: bool = False,
) -> ItemPage:
    owner = user.id if (mine or user.role != "admin") else None
    rows, next_cursor = store.list_items(owner_id=owner, after=cursor, limit=limit)
    return ItemPage(items=[r.public() for r in rows], next_cursor=next_cursor, count=len(rows))


@app.post("/items", status_code=201, tags=["items"])
def create_item(
    body: ItemCreate,
    user: Annotated[User, Depends(require_roles("editor", "admin"))],
) -> dict[str, Any]:
    item = store.create_item(user.id, body.name, body.price_cents, body.description)
    return item.public()


@app.get("/items/{item_id}", tags=["items"])
def get_item(item_id: str, user: Annotated[User, Depends(current_user)]) -> dict[str, Any]:
    item = store.get_item(item_id)
    if item is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "item not found")
    if item.owner_id != user.id and user.role != "admin":
        # 404 rather than 403: do not confirm that someone else's id exists.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "item not found")
    return item.public()


@app.patch("/items/{item_id}", tags=["items"])
def update_item(
    item_id: str,
    body: ItemUpdate,
    user: Annotated[User, Depends(require_roles("editor", "admin"))],
) -> dict[str, Any]:
    item = store.get_item(item_id)
    if item is None or (item.owner_id != user.id and user.role != "admin"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "item not found")
    updated = store.update_item(
        item_id, name=body.name, price_cents=body.price_cents, description=body.description
    )
    return updated.public()


@app.delete("/items/{item_id}", status_code=204, response_class=Response, tags=["items"])
def delete_item(item_id: str, user: Annotated[User, Depends(require_roles("admin"))]) -> Response:
    if not store.delete_item(item_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "item not found")
    return Response(status_code=204)


@app.post("/admin/users/{user_id}/role", tags=["admin"])
def set_role(
    user_id: str,
    role: str,
    user: Annotated[User, Depends(require_roles("admin"))],
) -> dict[str, Any]:
    if store.user_by_id(user_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    try:
        return store.set_role(user_id, role).public()
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
