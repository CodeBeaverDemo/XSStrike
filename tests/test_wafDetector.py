import io
import json
import pytest
import builtins  # Import builtins to patch the built-in open function

from core.wafDetector import wafDetector

# FakeResponse class to simulate the response from the requester function
class FakeResponse:
    def __init__(self, text, status_code, headers):
        self.text = text
        self.status_code = status_code
        self.headers = headers

# A fake open() function to simulate reading the wafSignatures.json file.
def fake_open(*args, **kwargs):
    json_content = json.dumps({
        "FakeWAF": {
            "page": "trigger",
            "code": "^403$",
            "headers": "header_trigger"
        },
        "NoMatchWAF": {
            "page": "nomatch",
            "code": "^599$",
            "headers": "notfound"
        }
    })
    return io.StringIO(json_content)

# A fake requester() that returns a FakeResponse.
def fake_requester(url, params, headers, GET, delay, timeout):
    # Use attributes attached to the function to simulate different responses.
    return FakeResponse(fake_requester.text, fake_requester.status_code, fake_requester.headers)


def test_code_below_400(monkeypatch):
    """Test wafDetector returns None when HTTP status code is below 400."""
    # Monkey-patch the open and requester in the wafDetector module.
    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr("core.wafDetector.requester", fake_requester)

    # Set the fake response attributes to simulate a safe page.
    fake_requester.text = "Safe page content"
    fake_requester.status_code = 200
    fake_requester.headers = {"Server": "Apache"}

    params = {}
    result = wafDetector("http://example.com", params, {"User-Agent": "test"}, True, 0, 5)
    # Ensure the noise payload was added.
    assert params.get("xss") == '<script>alert("XSS")</script>'
    assert result is None


def test_no_match(monkeypatch):
    """Test wafDetector returns None when the fingerprints do not match the response data."""
    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr("core.wafDetector.requester", fake_requester)

    fake_requester.text = "Page with safe content"
    fake_requester.status_code = 500
    fake_requester.headers = {"Server": "nginx"}

    params = {}
    result = wafDetector("http://example.com", params, {"User-Agent": "test"}, True, 0, 5)
    assert result is None


def test_match(monkeypatch):
    """Test wafDetector returns the matching WAF name when the response is consistent with a known fingerprint."""
    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr("core.wafDetector.requester", fake_requester)

    fake_requester.text = "This page includes trigger message"
    fake_requester.status_code = 403
    fake_requester.headers = {"X-Powered-By": "header_trigger"}

    params = {}
    result = wafDetector("http://example.com", params, {"User-Agent": "test"}, True, 0, 5)
    assert result == "FakeWAF"


def test_no_code(monkeypatch):
    """Test that wafDetector returns None when the response has no valid status code."""
    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr("core.wafDetector.requester", fake_requester)

    fake_requester.text = "Some content with trigger"
    fake_requester.status_code = None
    fake_requester.headers = {"X": "header_trigger"}

    params = {}
    result = wafDetector("http://example.com", params, {"User-Agent": "test"}, True, 0, 5)
    assert result is None
def fake_open_custom(*args, **kwargs):
    json_content = json.dumps({
        "WAF1": {"page": "alpha", "code": "^500$", "headers": "hdr1"},
        "WAF2": {"page": "alpha", "code": "^500$", "headers": "hdr2"}
    })
    return io.StringIO(json_content)

def fake_open_empty(*args, **kwargs):
    json_content = "{}"
    return io.StringIO(json_content)

def fake_open_empty_signatures(*args, **kwargs):
    json_content = json.dumps({
        "EmptyWAF": {"page": "", "code": "", "headers": ""}
    })
    return io.StringIO(json_content)

def test_multiple_matches(monkeypatch):
    """Test wafDetector returns the WAF with the highest score when multiple signatures match."""
    monkeypatch.setattr(builtins, "open", fake_open_custom)
    monkeypatch.setattr("core.wafDetector.requester", fake_requester)
    # Response that matches both signatures on page and code.
    # However, only WAF1 will have its header pattern matched.
    fake_requester.text = "This alpha content string"
    fake_requester.status_code = 500
    fake_requester.headers = {"Custom": "hdr1"}
    params = {}
    result = wafDetector("http://example.com", params, {"User-Agent": "test"}, True, 0, 5)
    assert result == "WAF1"

def test_empty_waf_signatures(monkeypatch):
    """Test that wafDetector returns None when the wafSignatures JSON file is empty."""
    monkeypatch.setattr(builtins, "open", fake_open_empty)
    monkeypatch.setattr("core.wafDetector.requester", fake_requester)
    fake_requester.text = "Content with trigger"
    fake_requester.status_code = 403
    fake_requester.headers = {"X": "header_trigger"}
    params = {}
    result = wafDetector("http://example.com", params, {"User-Agent": "test"}, True, 0, 5)
    assert result is None

def test_empty_signatures_fields(monkeypatch):
    """Test that wafDetector returns None when wafSignatures have empty fields."""
    monkeypatch.setattr(builtins, "open", fake_open_empty_signatures)
    monkeypatch.setattr("core.wafDetector.requester", fake_requester)
    fake_requester.text = "Any content that might match trigger"
    fake_requester.status_code = 404
    fake_requester.headers = {"Server": "Apache"}
    params = {}
    result = wafDetector("http://example.com", params, {"User-Agent": "test"}, True, 0, 5)
    assert result is None

def fake_open_header_only(*args, **kwargs):
    json_content = json.dumps({
        "HeaderOnly": {"page": "", "code": "", "headers": "header_only"}
    })
    return io.StringIO(json_content)

def test_header_only_match(monkeypatch):
    """Test that wafDetector detects a WAF based solely on header matching."""
    monkeypatch.setattr(builtins, "open", fake_open_header_only)
    monkeypatch.setattr("core.wafDetector.requester", fake_requester)
    fake_requester.text = "Non triggering text"
    fake_requester.status_code = 404
    fake_requester.headers = {"X": "header_only_value"}
    params = {}
    result = wafDetector("http://example.com", params, {"User-Agent": "test"}, True, 0, 5)
    assert result == "HeaderOnly"
def test_code_zero(monkeypatch):
    """Test that wafDetector returns None when HTTP status code is 0 (falsy)."""
    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr("core.wafDetector.requester", fake_requester)
    fake_requester.text = "Content with no triggering"
    fake_requester.status_code = 0
    fake_requester.headers = {"Server": "Apache"}
    params = {}
    result = wafDetector("http://example.com", params, {"User-Agent": "test"}, True, 0, 5)
    # xss payload should be injected regardless
    assert params.get("xss") == '<script>alert("XSS")</script>'
    assert result is None

def fake_open_equal(*args, **kwargs):
    json_content = json.dumps({
        "WAF1": {"page": "trigger", "code": "", "headers": ""},
        "WAF2": {"page": "trigger", "code": "", "headers": ""}
    })
    return io.StringIO(json_content)

def test_equal_score(monkeypatch):
    """Test that wafDetector returns the first matching WAF when two have equal scores."""
    monkeypatch.setattr(builtins, "open", fake_open_equal)
    monkeypatch.setattr("core.wafDetector.requester", fake_requester)
    # Both signatures will match the page text, giving them an equal score.
    fake_requester.text = "This text contains trigger somewhere."
    fake_requester.status_code = 403
    fake_requester.headers = {"Test": "none"}
    params = {}
    result = wafDetector("http://example.com", params, {"User-Agent": "test"}, True, 0, 5)
    # The first WAF in the JSON ("WAF1") is expected to win in the case of a tie.
    assert result == "WAF1"
def fake_open_code_only(*args, **kwargs):
    json_content = json.dumps({
        "CodeOnly": {"page": "", "code": "^403$", "headers": ""}
    })
    return io.StringIO(json_content)

def test_code_only_match(monkeypatch):
    """Test that wafDetector detects a WAF based solely on code signature matching."""
    monkeypatch.setattr(builtins, "open", fake_open_code_only)
    monkeypatch.setattr("core.wafDetector.requester", fake_requester)
    fake_requester.text = "Normal content that does not trigger page or header match"
    fake_requester.status_code = 403
    fake_requester.headers = {"X": "none"}
    params = {}
    result = wafDetector("http://example.com", params, {"User-Agent": "test"}, True, 0, 5)
    assert result == "CodeOnly"

def test_requester_exception(monkeypatch):
    """Test that wafDetector propagates an exception raised by the requester."""
    def fake_requester_exception(url, params, headers, GET, delay, timeout):
        raise Exception("Requester error")
    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr("core.wafDetector.requester", fake_requester_exception)
    params = {}
    with pytest.raises(Exception, match="Requester error"):
        wafDetector("http://example.com", params, {"User-Agent": "test"}, True, 0, 5)
    # Ensure that the payload was injected despite the exception.
    assert params.get("xss") == '<script>alert("XSS")</script>'