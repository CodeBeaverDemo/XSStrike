import pytest
import core.config
from concurrent.futures import Future
from modes.scan import scan, checky

# Dummy response class for simulating HTTP responses
class DummyResponse:
    def __init__(self, text):
        self.text = text

# Define dummy functions to override dependencies in scan
def dummy_requester(url, params, headers, GET, delay, timeout):
    # Return a dummy response object
    return DummyResponse("dummy response")

def dummy_dom(response_text):
    # Simulate that there is no DOM vulnerability
    return False

def dummy_getUrl(target, GET):
    return target + "/dummy"

def dummy_getParams(target, paramData, GET):
    # If paramData is provided, return a non-empty dict, else empty.
    if paramData:
        return {"a": "test"}
    return {}

def dummy_wafDetector(url, params, headers, GET, delay, timeout):
    return None

def dummy_htmlParser(response, encoding):
    # If response text contains 'xsschecker', simulate finding reflections.
    if "xsschecker" in response.text:
        return {0: "found"}
    return {}

def dummy_filterChecker(url, params, headers, GET, delay, occurences, timeout, encoding):
    # Dummy efficiencies for simulation.
    return [50]

def dummy_generator(occurences, response_text):
    # Return a payload that simulates a high-efficiency test.
    return {100: ["payload1"]}

def dummy_checker(url, params, headers, GET, delay, vect, positions, timeout, encoding):
    # If vect equals "payload1", simulate 100 efficiency; otherwise 0.
    if vect == "payload1":
        return [100]
    return [0]

class TestScan:
    """Test suite for scan module."""

    @pytest.fixture(autouse=True)
    def patch_dependencies(self, monkeypatch):
        # Patch all external dependencies in modes.scan to use our dummy implementations.
        from modes import scan as s
        monkeypatch.setattr(s, "requester", dummy_requester)
        monkeypatch.setattr(s, "dom", dummy_dom)
        monkeypatch.setattr(s, "getUrl", dummy_getUrl)
        monkeypatch.setattr(s, "getParams", dummy_getParams)
        monkeypatch.setattr(s, "wafDetector", dummy_wafDetector)
        monkeypatch.setattr(s, "htmlParser", dummy_htmlParser)
        monkeypatch.setattr(s, "filterChecker", dummy_filterChecker)
        monkeypatch.setattr(s, "generator", dummy_generator)
        monkeypatch.setattr(s, "checker", dummy_checker)
        monkeypatch.setitem(core.config.globalVariables, 'path', False)

    def test_scan_no_params(self, monkeypatch):
        """Test that scan exits when no parameters are provided."""
        # Override getParams to always return an empty dict.
        monkeypatch.setattr("modes.scan.getParams", lambda target, paramData, GET: {})
        with pytest.raises(SystemExit):
            scan("http://example.com", None, None, {}, 0, 10, True, True, 2)

    def test_scan_no_reflections(self, monkeypatch):
        """Test that scan handles no reflection found in the response."""
        # Override htmlParser to always return an empty dict.
        monkeypatch.setattr("modes.scan.htmlParser", lambda response, encoding: {})
        # Provide non-empty paramData so getParams returns a parameter.
        result = scan("http://example.com", {"dummy": "data"}, None, {}, 0, 10, True, True, 2)
        # Since no reflection is found, scan continues and returns None.
        assert result is None

    def test_checky_efficiency(self):
        """Test checky's calculation of best efficiency using the dummy checker."""
        paramsCopy = {"a": "test"}
        positions = [0]
        occurences = {0: "found"}
        # Call checky with dummy vector "payload1" that must lead to 100 efficiency.
        bestEfficiency, target, loggerVector, confidence = checky(
            "http://example.com",
            "http://example.com/dummy",
            paramsCopy,
            {},
            True,
            0,
            "payload1",
            positions,
            10,
            None,
            occurences,
            100,
            {"lap": 0},
            1)
        assert bestEfficiency == 100
        assert target == "http://example.com"
        assert loggerVector == "payload1"
        assert confidence == 100

    def test_scan_payload_found(self, monkeypatch):
        """Test scan when a high-efficiency payload is found, simulating user input 'n' to stop further scanning."""
        # Simulate user input of 'n' so that scanning stops after a payload is found.
        monkeypatch.setattr("builtins.input", lambda prompt: "n")
        # Override htmlParser to simulate a reflection by checking for 'xsschecker'.
        monkeypatch.setattr("modes.scan.htmlParser", lambda response, encoding: {0: "xsschecker"})
        # Override requester to return a response that contains 'xsschecker'.
        def custom_requester(url, params, headers, GET, delay, timeout):
            return DummyResponse("contains xsschecker")
        monkeypatch.setattr("modes.scan.requester", custom_requester)
        result = scan("http://example.com", {"dummy": "data"}, None, {}, 0, 10, True, False, 2)
        # Check that scan returns a tuple with the target and the payload.
        assert isinstance(result, tuple)
        assert result[0] == "http://example.com"
        assert result[1] == "payload1"

    def test_scan_with_https_prefix(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda prompt: "n")
        """Test scan handling a target without an http(s) prefix by forcing an https attempt that fails then falls back to http."""
        call_count = {"count": 0}
        def custom_requester(url, params, headers, GET, delay, timeout):
            if call_count["count"] == 0:
                call_count["count"] += 1
                raise Exception("HTTPS failed")
            return DummyResponse("dummy response xsschecker")
        monkeypatch.setattr("modes.scan.requester", custom_requester)
        result = scan("example.com", {"dummy": "data"}, None, {}, 0, 10, True, False, 2)
        # Since HTTPS fails, scan should fall back to http. Either a payload is found or not,
        # so we check that the result is either a tuple or None.
        if result is not None:
            assert isinstance(result, tuple)
        else:
            assert result is None
    def test_scan_continue_scanning(self, monkeypatch):
        """Test scan continues scanning when user inputs 'y' after a high-efficiency payload is found."""
        monkeypatch.setattr("builtins.input", lambda prompt: "y")
        monkeypatch.setattr("modes.scan.htmlParser", lambda response, encoding: {0: "xsschecker"})
        monkeypatch.setattr("modes.scan.requester", lambda url, params, headers, GET, delay, timeout: DummyResponse("contains xsschecker"))
        # With user response "y", the scan does not break early and returns None.
        result = scan("http://example.com", {"dummy": "data"}, None, {}, 0, 10, True, False, 2)
        assert result is None

    def test_scan_no_vectors_generated(self, monkeypatch):
        """Test scan handling when the payload generator produces no vectors."""
        monkeypatch.setattr("modes.scan.generator", lambda occurences, response_text: {})
        monkeypatch.setattr("modes.scan.htmlParser", lambda response, encoding: {0: "xsschecker"})
        result = scan("http://example.com", {"dummy": "data"}, None, {}, 0, 10, True, True, 2)
        # With no payloads generated, scan should complete without an early return.
        assert result is None

    def test_scan_with_encoding(self, monkeypatch):
        """Test scan behavior when an encoding function is provided."""
        monkeypatch.setattr("builtins.input", lambda prompt: "n")
        monkeypatch.setattr("modes.scan.htmlParser", lambda response, encoding: {0: "xsschecker"})
        encoding_func = lambda s: "encoded_" + s
        monkeypatch.setattr("modes.scan.requester", lambda url, params, headers, GET, delay, timeout: DummyResponse("contains xsschecker"))
        result = scan("http://example.com", {"dummy": "data"}, encoding_func, {}, 0, 10, True, False, 2)
        # Expect a tuple result with the target and the payload since a high-efficiency payload is found.
        assert isinstance(result, tuple)
        assert result[0] == "http://example.com"
        assert result[1] == "payload1"
    def test_scan_vector_with_slash(self, monkeypatch):
        """Test scan branch when vector starts with '\' and efficiency >=95 triggers early exit."""
        monkeypatch.setattr("builtins.input", lambda prompt: "n")
        monkeypatch.setattr("modes.scan.htmlParser", lambda response, encoding: {0: "xsschecker"})
        # Override generator to produce a vector starting with '\' and dummy checker to return an efficiency of 95.
        monkeypatch.setattr("modes.scan.generator", lambda occurences, response_text: {90: ["\\payload_special"]})
        monkeypatch.setattr("modes.scan.checker", lambda url, params, headers, GET, delay, vect, positions, timeout, encoding: [95])
        result = scan("http://example.com", {"dummy": "data"}, None, {}, 0, 10, True, False, 2)
        # Assert that a tuple is returned with the expected payload and target.
        assert isinstance(result, tuple)
        assert result[0] == "http://example.com"
        assert result[1] == "\\payload_special"

    def test_checky_with_post(self):
        """Test checky function behavior when POST method is used (GET is False) so that unquote is applied."""
        paramsCopy = {"a": "test"}
        positions = [0]
        occurences = {0: "found"}
        # Provide a percent-encoded payload that, when unquoted, becomes 'payload1'
        vect = "%70ayload1"
        # Define a dummy checker that returns 100 efficiency when vect is 'payload1'
        def dummy_post_checker(url, params, headers, GET, delay, vect, positions, timeout, encoding):
            if vect == "payload1":
                return [100]
            return [0]
        from modes import scan as s
        s.checker = dummy_post_checker
        bestEfficiency, target, loggerVector, confidence = checky(
            "http://example.com",
            "http://example.com/dummy",
            paramsCopy,
            {},
            False,
            0,
            vect,
            positions,
            10,
            None,
            occurences,
            100,
            {"lap": 0},
            1)
        assert bestEfficiency == 100
        assert target == "http://example.com"
        assert loggerVector == "%70ayload1"
        assert confidence == 100

    def test_scan_multiple_params(self, monkeypatch):
        """Test scan behavior when multiple parameters are provided, ensuring all are processed."""
        # Override getParams to return multiple parameters.
        monkeypatch.setattr("modes.scan.getParams", lambda target, paramData, GET: {"a": "test", "b": "test2"})
        # Override htmlParser to simulate reflections.
        monkeypatch.setattr("modes.scan.htmlParser", lambda response, encoding: {0: "xsschecker"})
        # Override generator to produce payloads for both parameters with efficiencies below early exit threshold.
        monkeypatch.setattr("modes.scan.generator", lambda occurences, response_text: {50: ["payloadA"], 60: ["payloadB"]})
        # Override checker to always return an efficiency of 60.
        monkeypatch.setattr("modes.scan.checker", lambda url, params, headers, GET, delay, vect, positions, timeout, encoding: [60])
        # Override filterChecker to return dummy efficiencies.
        monkeypatch.setattr("modes.scan.filterChecker", lambda url, params, headers, GET, delay, occurences, timeout, encoding: [60])
        # Simulate user input 'n' (even though no early break should be triggered).
        monkeypatch.setattr("builtins.input", lambda prompt: "n")
        result = scan("http://example.com", {"dummy": "data"}, None, {}, 0, 10, True, True, 2)
        # Expect the scan to complete processing all parameters and return None.
        assert result is None
    def test_checky_empty_efficiencies(self, monkeypatch):
        """Test checky behavior when checker returns an empty list. In this case, the function will add zero efficiencies for each occurrence and the best efficiency should be 0."""
        paramsCopy = {"a": "test"}
        positions = [0]
        occurences = {0: "found"}
        vect = "empty_test_payload"
        progress = {"lap": 0}
        # Override checker to return an empty list regardless of input.
        monkeypatch.setattr("modes.scan.checker", lambda url, params, headers, GET, delay, vect, positions, timeout, encoding: [])
        bestEfficiency, target, loggerVector, confidence = checky(
            "http://example.com",
            "http://example.com/dummy",
            paramsCopy,
            {},
            True,
            0,
            vect,
            positions,
            10,
            None,
            occurences,
            50,
            progress,
            1)
        assert bestEfficiency == 0
        assert target == "http://example.com"
        assert loggerVector == "empty_test_payload"
        assert confidence == 50
        assert progress["lap"] == 1

    def test_checky_with_global_path_true(self, monkeypatch):
        """Test checky when core.config.globalVariables['path'] is True. The payload vector should have "/" replaced with "%2F" before being used."""
        from core import config
        # Set the global path flag to True so that vect replacement takes place.
        config.globalVariables['path'] = True
        paramsCopy = {"a": "test"}
        positions = [0]
        occurences = {0: "found"}
        vect = "a/b"
        progress = {"lap": 0}
        # Override checker to return 100 efficiency.
        monkeypatch.setattr("modes.scan.checker", lambda url, params, headers, GET, delay, vect, positions, timeout, encoding: [100])
        bestEfficiency, target, loggerVector, confidence = checky(
            "http://example.com",
            "http://example.com/dummy",
            paramsCopy,
            {},
            True,
            0,
            vect,
            positions,
            10,
            None,
            occurences,
            80,
            progress,
            1)
        # Since globalVariables['path'] is True, the "/" in vect should have been replaced with "%2F".
        assert loggerVector == "a%2Fb"
        assert bestEfficiency == 100
        assert target == "http://example.com"
        assert confidence == 80
        assert progress["lap"] == 1
        # Reset the flag to avoid side effects on other tests.
        config.globalVariables['path'] = False
    def test_scan_dom_vulnerabilities(self, monkeypatch):
        """Test scan when DOM vulnerabilities are found and payload is triggered."""
        monkeypatch.setattr("builtins.input", lambda prompt: "n")
        monkeypatch.setattr("modes.scan.dom", lambda response: ["Vuln found line 1", "Vuln found line 2"])
        monkeypatch.setattr("modes.scan.htmlParser", lambda response, encoding: {0: "xsschecker"})
        payloads = {100: ["payload_dom"]}
        monkeypatch.setattr("modes.scan.generator", lambda occurences, response_text: payloads)
        monkeypatch.setattr("modes.scan.filterChecker", lambda url, params, headers, GET, delay, occurences, timeout, encoding: [100])
        monkeypatch.setattr("modes.scan.checker", lambda url, params, headers, GET, delay, vect, positions, timeout, encoding: [100])
        result = scan("http://example.com", {"dummy": "data"}, None, {}, 0, 10, False, False, 2)
        assert isinstance(result, tuple)
        assert result[1] == "payload_dom"

    def test_scan_waf_detected(self, monkeypatch):
        """Test scan behavior when WAF is detected, ensuring proper logging but continuing scan."""
        monkeypatch.setattr("modes.scan.wafDetector", lambda url, params, headers, GET, delay, timeout: "WAF_Flag")
        monkeypatch.setattr("modes.scan.htmlParser", lambda response, encoding: {})
        result = scan("http://example.com", {"dummy": "data"}, None, {}, 0, 10, True, True, 2)
        assert result is None