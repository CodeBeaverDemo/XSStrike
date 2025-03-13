import time
import requests
import random
import pytest

from urllib3.exceptions import ProtocolError
from core.requester import requester

# Import the module so we can patch its attributes (getVar, converter, logger)
import core.requester as requester_mod

class DummyResponse:
    def __init__(self, text="dummy response", status_code=200):
        self.text = text
        self.status_code = status_code

def dummy_converter(data, url=None):
    """A dummy converter that appends '_converted' to its input."""
    if url:
        return url + "_converted"
    return str(data) + "_converted"

@pytest.fixture(autouse=True)
def patch_getVar(monkeypatch):
    """Patch getVar to return False by default for any key."""
    monkeypatch.setattr(requester_mod, 'getVar', lambda key: False)

@pytest.fixture(autouse=True)
def patch_converter(monkeypatch):
    """Patch converter to use our dummy_converter."""
    monkeypatch.setattr(requester_mod, 'converter', dummy_converter)

class DummyLogger:
    def debug(self, msg): pass
    def debug_json(self, msg, obj): pass
    def warning(self, msg): pass

@pytest.fixture(autouse=True)
def patch_logger(monkeypatch):
    """Patch logger with a dummy logger to avoid real logging during tests."""
    monkeypatch.setattr(requester_mod, 'logger', DummyLogger())

@pytest.fixture(autouse=True)
def patch_sleep(monkeypatch):
    """Patch time.sleep to avoid delay during tests."""
    monkeypatch.setattr(time, 'sleep', lambda x: None)

def test_requester_get(monkeypatch):
    """Test that a GET request is made correctly when GET flag is True."""
    test_headers = {}  # no User-Agent given
    test_data = {'param': 'value'}
    test_url = "http://example.com"

    def dummy_get(url, params, headers, timeout, verify, proxies):
        assert url == test_url
        assert params == test_data
        # Ensure headers gets a valid User-Agent (injected randomly)
        assert 'User-Agent' in headers and headers['User-Agent'] != ''
        return DummyResponse(text="GET success")

    monkeypatch.setattr(requests, 'get', dummy_get)

    response = requester(test_url, test_data, test_headers, GET=True, delay=0, timeout=5)
    assert response.text == "GET success"

def test_requester_post_json(monkeypatch):
    """Test that a POST request with json data is executed when getVar('jsonData') returns True."""
    # Patch getVar: return True for 'jsonData', False otherwise.
    custom_getvar = lambda key: True if key == 'jsonData' else False
    monkeypatch.setattr(requester_mod, 'getVar', custom_getvar)

    test_headers = {'User-Agent': '$'}  # This should be replaced with a random user-agent.
    test_data = {'key': 'value'}
    test_url = "http://example.com"

    def dummy_post(url, json, headers, timeout, verify, proxies):
        assert url == test_url
        # dummy_converter converts dict to string with '_converted' appended
        expected = str(test_data) + "_converted"
        assert json == expected
        # Ensure user-agent is replaced and is not '$'
        assert headers['User-Agent'] != '$'
        return DummyResponse(text="POST json success")

    monkeypatch.setattr(requests, 'post', dummy_post)

    response = requester(test_url, test_data, test_headers, GET=False, delay=0, timeout=5)
    assert response.text == "POST json success"

def test_requester_post_regular(monkeypatch):
    """Test that a regular POST request (with form data) executes correctly."""
    test_headers = {'User-Agent': 'TestAgent'}
    test_data = {'key': 'value'}
    test_url = "http://example.com"

    def dummy_post(url, data, headers, timeout, verify, proxies):
        assert url == test_url
        # When not converting, the data stays the same.
        assert data == test_data
        # Ensure the given User-Agent remains unchanged.
        assert headers['User-Agent'] == 'TestAgent'
        return DummyResponse(text="POST regular success")

    monkeypatch.setattr(requests, 'post', dummy_post)

    response = requester(test_url, test_data, test_headers, GET=False, delay=0, timeout=5)
    assert response.text == "POST regular success"

def test_requester_path(monkeypatch):
    """Test that when getVar('path') returns True, the URL is converted and data is cleared."""
    # Patch getVar: return True for 'path', False otherwise.
    custom_getvar = lambda key: True if key == 'path' else False
    monkeypatch.setattr(requester_mod, 'getVar', custom_getvar)

    test_headers = {}
    test_data = "data"  # will be passed to converter
    test_url = "http://example.com"

    def dummy_get(url, params, headers, timeout, verify, proxies):
        # After conversion, the url should have been appended with '_converted'
        assert url == test_url + "_converted"
        # data should become [] per the implementation
        assert params == []
        return DummyResponse(text="GET path success")

    monkeypatch.setattr(requests, 'get', dummy_get)

    response = requester(test_url, test_data, test_headers, GET=False, delay=0, timeout=5)
    assert response.text == "GET path success"

def test_protocol_exception(monkeypatch):
    """Test that a ProtocolError is handled by logging a warning and sleeping for 10 minutes."""
    test_headers = {}
    test_data = {'param': 'value'}
    test_url = "http://example.com"

    def raising_get(*args, **kwargs):
        raise ProtocolError("protocol error")

    # Use a mutable container to flag that sleep was called.
    sleep_called = [False]
    def dummy_sleep(duration):
        sleep_called[0] = True

    monkeypatch.setattr(requests, 'get', raising_get)
    monkeypatch.setattr(time, 'sleep', dummy_sleep)

    response = requester(test_url, test_data, test_headers, GET=True, delay=0, timeout=5)
    # The ProtocolError except block should have been executed.
    assert sleep_called[0] is True
    # Function does not return a response in ProtocolError case.
    assert response is None

def test_general_exception(monkeypatch):
    """Test that a general Exception is handled by returning an empty requests.Response object."""
    test_headers = {}
    test_data = {'param': 'value'}
    test_url = "http://example.com"

    def raising_get(*args, **kwargs):
        raise Exception("general error")

    monkeypatch.setattr(requests, 'get', raising_get)

    response = requester(test_url, test_data, test_headers, GET=True, delay=0, timeout=5)
    # When a generic Exception is raised, an instance of requests.Response is returned.
    assert isinstance(response, requests.Response)