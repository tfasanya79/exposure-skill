
from datetime import date, timedelta

from exposure_skill import scope as scope_mod


def base():
    return {
        "authorised": True,
        "authorisation_reference": "TICKET-1",
        "expires": (date.today() + timedelta(days=30)).isoformat(),
        "targets": ["example.com"],
    }


def test_valid_scope_passes():
    assert scope_mod.validate(base(), "example.com") == []


def test_missing_authorisation_blocks():
    data = base()
    data["authorised"] = False
    assert scope_mod.validate(data, "example.com")


def test_empty_reference_blocks():
    data = base()
    data["authorisation_reference"] = "   "
    assert scope_mod.validate(data, "example.com")


def test_expired_scope_blocks():
    data = base()
    data["expires"] = (date.today() - timedelta(days=1)).isoformat()
    assert scope_mod.validate(data, "example.com")


def test_target_outside_scope_blocks():
    assert scope_mod.validate(base(), "someone-else.com")


def test_no_send_posture_grades_a(monkeypatch=None):
    from exposure_skill import checks

    original = checks._dig

    def fake(name, rtype):
        if name == "quiet.example" and rtype == "TXT":
            return ["v=spf1 -all"]
        if name == "_dmarc.quiet.example" and rtype == "TXT":
            return ["v=DMARC1; p=reject; rua=mailto:postmaster@quiet.example"]
        return []

    checks._dig = fake
    try:
        result = checks.dns_auth("quiet.example")
    finally:
        checks._dig = original
    assert result["grade"] == "A", result
