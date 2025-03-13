import logging
import sys
import json
import io
import pytest

from core.log import setup_logger, console_log_level, file_log_level, log_file, log_config

class TestLogger:
    """Test suite for custom logging from xsstrike's core.log"""

    def setup_logger_instance(self, name="testlogger"):
        """Helper method to create a logger instance using setup_logger"""
        return setup_logger(name)

    def test_setup_logger_attributes(self):
        """Test that the logger has the expected custom methods and handlers."""
        logger = self.setup_logger_instance()
        # Check that at least one StreamHandler exists
        assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)
        # Check custom methods are attached to the logger
        assert hasattr(logger, "red_line")
        assert hasattr(logger, "yellow_summary_line")
        assert hasattr(logger, "no_format")
        assert hasattr(logger, "debug_json")

    def test_basic_logging(self, capsys):
        """Test basic logging at INFO and ERROR levels and capture their output."""
        logger = self.setup_logger_instance()
        logger.info("info message")
        logger.error("error message")
        captured = capsys.readouterr().out
        assert "info message" in captured
        assert "error message" in captured

    def test_custom_levels(self, capsys):
        """Test custom logging levels VULN, RUN, and GOOD produce output."""
        logger = self.setup_logger_instance()
        logger.vuln("vuln message")
        logger.run("run message")
        logger.good("good message")
        captured = capsys.readouterr().out
        # Check that messages corresponding to custom levels are present
        assert "vuln message" in captured
        assert "run message" in captured
        assert "good message" in captured

    def test_no_format_logging(self, capsys):
        """Test logging without formatting using the no_format method."""
        logger = self.setup_logger_instance()
        logger.no_format("plain message", level='INFO')
        captured = capsys.readouterr().out
        # The output should contain the plain message without extra formatting prefixes
        assert "plain message" in captured
        # Check that typical formatting characters (such as '[') are absent in the output
        assert ('[' not in captured) or (']' not in captured)

    def test_debug_json(self):
        """Test the debug_json method using a StringIO stream to capture logger output."""
        logger = self.setup_logger_instance()
        logger.setLevel(logging.DEBUG)
        import io
        buf = io.StringIO()
        test_handler = logging.StreamHandler(buf)
        test_handler.setLevel(logging.DEBUG)
        test_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(test_handler)
        # Test debug_json with dictionary data
        logger.debug_json("debug dict", {"a": 1})
        test_handler.flush()
        output = buf.getvalue()
        assert ('"a": 1' in output) or ("'a': 1" in output)
        # Clear buffer for next test
        buf.truncate(0)
        buf.seek(0)
        # Test debug_json with non-dictionary data
        logger.debug_json("debug non-dict", "simple string")
        test_handler.flush()
        output = buf.getvalue()
        assert "simple string" in output
        # Clean up: remove test handler
        logger.removeHandler(test_handler)

    def test_red_line_and_yellow_summary_line(self, capsys):
        """Test the red_line and yellow_summary_line methods produce expected patterns."""
        logger = self.setup_logger_instance()
        # Test red_line: should log a line with a repeated '-' pattern of specified length
        logger.red_line(amount=10, level='ERROR')
        output_red = capsys.readouterr().out
        assert '-' * 10 in output_red

        # Test yellow_summary_line: should log a line with a repeated '=' pattern of specified length
        logger.yellow_summary_line(amount=15, level='INFO')
        output_yellow = capsys.readouterr().out
        assert '=' * 15 in output_yellow

    def test_file_logging(self, tmp_path, monkeypatch):
        """Test that file logging is set up correctly when file_log_level is enabled."""
        # Temporarily enable file logging by setting file_log_level to DEBUG
        from core import log as core_log
        monkeypatch.setattr(core_log, 'file_log_level', 'DEBUG')
        test_log_file = tmp_path / "test_xsstrike.log"
        monkeypatch.setattr(core_log, 'log_file', str(test_log_file))
        logger = setup_logger("filelogger")
        # Log a debug message that should be written to the file
        logger.debug("debug file message")
        # Ensure that the file_handler attribute is present (indicating file logging is active)
        assert hasattr(logger, "file_handler")
        # Flush handlers so that content is written to the file
        for handler in logger.handlers:
            if hasattr(handler, "flush"):
                handler.flush()
        # Read the file and check that it contains the debug message
        log_contents = test_log_file.read_text()
        assert "debug file message" in log_contents
    def test_debug_json_non_serializable(self):
        """Test the debug_json method with non-JSON serializable data and ensure fallback logging."""
        logger = self.setup_logger_instance()
        logger.setLevel(logging.DEBUG)
        import io
        buf = io.StringIO()
        test_handler = logging.StreamHandler(buf)
        test_handler.setLevel(logging.DEBUG)
        test_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(test_handler)
        # Provide non-serializable data (a set) to force a TypeError in json.dumps
        logger.debug_json("test nonserializable", {"a": set([1])})
        test_handler.flush()
        output = buf.getvalue()
        # Check that the fallback logging logged the message and a string representation of the data
        assert "test nonserializable" in output
        assert "set(" in output or "{" in output
        logger.removeHandler(test_handler)

    def test_non_recognized_level_in_no_format(self, capsys):
        """Test that no_format logs using INFO level when an unrecognized level is provided."""
        logger = self.setup_logger_instance()
        # Calling no_format with an undefined logging level should fallback to info level logging
        logger.no_format("fallback message", level="NONEXISTENT")
        captured = capsys.readouterr().out
        assert "fallback message" in captured

    def test_custom_handler_terminator(self):
        """Test that CustomStreamHandler uses a custom terminator for messages ending with '\\r'."""
        from core.log import CustomStreamHandler
        import io
        stream = io.StringIO()
        handler = CustomStreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        # Create a LogRecord with a message ending in a carriage return
        record = logging.LogRecord("test", logging.INFO, "", 0, "line ending with carriage return\r", None, None)
        handler.emit(record)
        output = stream.getvalue()
        # Verify that the output ends with '\r'
        assert output.endswith("\r")
    def test_custom_formatter_prefix(self):
        """Test that CustomFormatter adds the correct prefix for levels present in log_config."""
        from core.log import CustomFormatter
        from logging import LogRecord
        # Temporarily override the INFO prefix to a known value for testing
        original_prefix = log_config['INFO']['prefix']
        log_config['INFO']['prefix'] = "INFO_PREFIX"
        record = LogRecord("test", logging.INFO, "", 0, "dummy", None, None)
        formatter = CustomFormatter("%(message)s")
        formatted_message = formatter.format(record)
        # Restore original prefix
        log_config['INFO']['prefix'] = original_prefix
        assert formatted_message.startswith("INFO_PREFIX")
        assert "dummy" in formatted_message

    def test_setup_logger_idempotency(self):
        """Test that calling setup_logger multiple times with the same name does not duplicate handlers or remove custom methods."""
        # Create a logger instance using our helper.
        logger1 = self.setup_logger_instance("dup")
        initial_handlers = logger1.handlers.copy()

        # Call setup_logger again for the same logger name.
        logger2 = setup_logger("dup")
        # They should be the same instance.
        assert logger1 is logger2
        # Custom methods should remain attached.
        assert hasattr(logger2, "red_line")
        assert hasattr(logger2, "yellow_summary_line")
        # All initially attached handlers should still be present.
        for handler in initial_handlers:
            assert handler in logger2.handlers

        # Also check that repeated configuration does not cause duplicate logging output.
        import io
        buf = io.StringIO()
        temp_handler = logging.StreamHandler(buf)
        temp_handler.setLevel(logging.DEBUG)
        temp_handler.setFormatter(logging.Formatter("%(message)s"))
        logger1.addHandler(temp_handler)
        logger1.info("dup test")
        temp_handler.flush()
        output = buf.getvalue()
        # We expect the message to appear only once.
        assert output.count("dup test") == 1
        logger1.removeHandler(temp_handler)

    def test_handler_switching(self, capsys):
        """Test that the logger correctly switches between no format and default format handlers."""
        logger = self.setup_logger_instance()
        # Save a reference to the default console handler.
        default_handler = logger.console_handler
        # Call no_format to log a message using a blank formatter.
        logger.no_format("switch test", level="INFO")
        # After the no_format method has been called the default handler should be re-attached.
        assert default_handler in logger.handlers