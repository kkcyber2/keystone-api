from keystone.ratelimit import RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_burst_up_to_capacity_then_refuse():
    clock = FakeClock()
    rl = RateLimiter(capacity=3, window=60, clock=clock)
    assert [rl.check("k")[0] for _ in range(3)] == [True, True, True]
    allowed, retry_after = rl.check("k")
    assert allowed is False
    assert retry_after > 0


def test_bucket_refills_over_time():
    clock = FakeClock()
    rl = RateLimiter(capacity=2, window=10, clock=clock)
    rl.check("k")
    rl.check("k")
    assert rl.check("k")[0] is False
    clock.advance(5)  # half the window -> one token back
    assert rl.check("k")[0] is True


def test_keys_are_independent():
    clock = FakeClock()
    rl = RateLimiter(capacity=1, window=60, clock=clock)
    assert rl.check("a")[0] is True
    assert rl.check("b")[0] is True
    assert rl.check("a")[0] is False


def test_reset_clears_state():
    clock = FakeClock()
    rl = RateLimiter(capacity=1, window=60, clock=clock)
    rl.check("a")
    rl.reset("a")
    assert rl.check("a")[0] is True


def test_invalid_construction():
    import pytest

    with pytest.raises(ValueError):
        RateLimiter(capacity=0, window=10)
    with pytest.raises(ValueError):
        RateLimiter(capacity=1, window=0)


def test_middleware_returns_429_with_retry_after(client, monkeypatch):
    from keystone import app as app_module

    app_module.limiter.reset()
    app_module.limiter.capacity = 2.0
    app_module.limiter.window = 60.0
    codes = [client.get("/health").status_code for _ in range(3)]
    assert codes[0] == 200
    # /health is exempt, so hammer a protected route instead
    app_module.limiter.reset()
    app_module.limiter.capacity = 1.0
    first = client.get("/items")
    second = client.get("/items")
    assert first.status_code == 401  # unauthenticated, but counted
    assert second.status_code == 429
    assert "retry-after" in {k.lower() for k in second.headers}
