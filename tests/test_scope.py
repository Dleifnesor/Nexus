import pytest

from nexus.config import Mode
from nexus.scope.scope import Scope, ScopeError


def test_ip_and_cidr_matching():
    s = Scope.parse(Mode.SCOPE, ["10.0.0.0/24", "192.168.1.5"])
    assert s.contains("10.0.0.55")
    assert s.contains("192.168.1.5")
    assert not s.contains("10.0.1.1")
    assert not s.contains("8.8.8.8")


def test_domain_and_subdomain_matching():
    s = Scope.parse(Mode.SCOPE, ["example.com"])
    assert s.contains("example.com")
    assert s.contains("api.example.com")
    assert s.contains("https://www.example.com/path")
    assert not s.contains("notexample.com")
    assert not s.contains("example.org")


def test_url_and_port_extraction():
    s = Scope.parse(Mode.SCOPE, ["example.com", "10.0.0.0/8"])
    assert s.contains("http://example.com:8080/admin")
    assert s.contains("10.5.5.5:443")


def test_sandbox_allows_everything():
    s = Scope.parse(Mode.SANDBOX, [])
    assert s.contains("8.8.8.8")
    assert s.contains("anything.example.org")
    s.enforce("8.8.8.8", "test")  # must not raise


def test_scope_enforce_raises_out_of_scope():
    s = Scope.parse(Mode.SCOPE, ["example.com"])
    with pytest.raises(ScopeError):
        s.enforce("evil.org", "nmap")


def test_empty_scope():
    s = Scope.parse(Mode.SCOPE, [])
    assert s.is_empty()
    assert not s.contains("example.com")


def test_ipv6():
    s = Scope.parse(Mode.SCOPE, ["2001:db8::/32"])
    assert s.contains("2001:db8::1")
    assert not s.contains("2001:dead::1")
