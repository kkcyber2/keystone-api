# Keystone API

A small but production-shaped REST service: stateless JWT auth, role-based access
control, per-identity rate limiting, cursor pagination and a generated OpenAPI schema.

It exists to show the parts of an API that are easy to get wrong — authorisation that
is enforced centrally rather than remembered per handler, pagination that stays stable
while rows are inserted, and rate limiting that degrades politely.

## Why it is built this way

* **Auth is stateless.** HS256 tokens signed with a secret from the environment. No
  session table, no sticky load balancer.
* **Authorisation is a dependency, not a habit.** Every protected route declares the
  roles it accepts. A new route cannot ship without a check because the check is part
  of the route signature.
* **Rate limiting is a token bucket.** Bursts are allowed up to the bucket size, then
  the caller is asked to slow down with a `Retry-After` header.
* **Pagination is cursor-based.** Offset pagination silently skips or repeats rows when
  the underlying collection changes; a cursor over a stable sort key does not.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
uvicorn keystone.app:app --reload
```

Then open <http://127.0.0.1:8000/docs>.

## Try it

```bash
# register the first user (becomes admin)
curl -s localhost:8000/auth/register -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"correct-horse-battery"}'

# log in and keep the token
TOKEN=$(curl -s localhost:8000/auth/login -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"correct-horse-battery"}' | python -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')

# create an item
curl -s localhost:8000/items -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"name":"first","price_cents":1999}'

# list it back
curl -s "localhost:8000/items?limit=10" -H "authorization: Bearer $TOKEN"
```

## Roles

| Role | Can |
|---|---|
| `viewer` | read items it owns |
| `editor` | create and update its own items |
| `admin` | read and write everything, delete, manage users |

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `KEYSTONE_SECRET` | dev value | JWT signing secret — **set this in production** |
| `KEYSTONE_TOKEN_TTL` | `3600` | token lifetime in seconds |
| `KEYSTONE_RATE_LIMIT` | `60` | requests per window per identity |
| `KEYSTONE_RATE_WINDOW` | `60` | window length in seconds |

## Tests

```bash
pytest -q
```

## License

MIT — see `LICENSE`.
