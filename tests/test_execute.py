# test_execute.py

from __future__ import annotations
import os
import time
import pytest

from forensics_copilot import execute as execute_mod
from forensics_copilot.execute import execute_suggestion, _execute
from forensics_copilot.model import AnalysisReport, Suggestion, SuggestionStatus


def make_suggestion(tool_hint, target_abs_path, **overrides) -> Suggestion:
    defaults = dict(
        id=1,
        target_file=os.path.basename(target_abs_path),
        target_abs_path=target_abs_path,
        action="test action",
        reason="test reason",
        tool_hint=tool_hint,
    )
    defaults.update(overrides)
    return Suggestion(**defaults)


class TestExecuteBasics:
    def test_real_tool_runs_successfully(self, tmp_path):
        target = tmp_path / "hello.txt"
        target.write_text("hello world")

        s = make_suggestion("file", str(target))
        _execute(s)

        assert s.status == SuggestionStatus.DONE
        assert s.result.returncode == 0
        assert s.result.error is None
        assert "ASCII text" in s.result.stdout or "text" in s.result.stdout.lower()

    def test_missing_tool_fails_with_friendly_hint_not_raw_exception(self, tmp_path):
        target = tmp_path / "photo.jpg"
        target.write_bytes(b"\xff\xd8\xff\xe0fake jpeg bytes")

        # Temporarily register a fake tool that's guaranteed not to exist on
        # any machine, instead of relying on exiftool specifically being
        import forensics_copilot.execute as execute_mod
        original_commands = dict(execute_mod._TOOL_COMMANDS)
        original_hints = dict(execute_mod._INSTALL_HINTS)
        execute_mod._TOOL_COMMANDS["definitely_not_a_real_tool"] = ["definitely_not_a_real_tool_xyz123", "{target}"]
        try:
            s = make_suggestion("definitely_not_a_real_tool", str(target))
            _execute(s)  # must not raise
        finally:
            execute_mod._TOOL_COMMANDS.clear()
            execute_mod._TOOL_COMMANDS.update(original_commands)
            execute_mod._INSTALL_HINTS.clear()
            execute_mod._INSTALL_HINTS.update(original_hints)

        assert s.status == SuggestionStatus.FAILED
        assert s.result.error is not None
        assert "not installed" in s.result.error.lower() or "not found" in s.result.error.lower()

    def test_unwired_tool_is_skipped_not_attempted(self, tmp_path):
        target = tmp_path / "data.bin"
        target.write_bytes(b"some bytes")

        s = make_suggestion("binwalk", str(target))
        _execute(s)

        assert s.status == SuggestionStatus.SKIPPED
        assert "not wired up" in s.result.error

    def test_no_tool_hint_is_skipped(self, tmp_path):
        target = tmp_path / "data.bin"
        target.write_bytes(b"some bytes")

        s = make_suggestion(None, str(target))
        _execute(s)

        assert s.status == SuggestionStatus.SKIPPED

    def test_missing_target_file_fails_cleanly(self):
        s = make_suggestion("file", "/no/such/path/exists.txt")
        _execute(s)

        assert s.status == SuggestionStatus.FAILED
        assert "no longer exists" in s.result.error


class TestExecuteUsesRealPathNotDisplayPath:
    def test_nested_display_path_is_not_used_as_filesystem_path(self, tmp_path):
        real_file = tmp_path / "actual_extracted_file.txt"
        real_file.write_text("hello")

        s = make_suggestion(
            "file",
            str(real_file),
            target_file="outer.zip/inner.zip/actual_extracted_file.txt",
        )
        _execute(s)

        assert s.status == SuggestionStatus.DONE
        assert s.result.command[-1] == str(real_file)


class TestExecuteSuggestionById:
    def test_executes_and_mutates_suggestion_in_report(self, tmp_path):
        target = tmp_path / "hello.txt"
        target.write_text("hello world")

        suggestion = make_suggestion("file", str(target), id=7)
        report = AnalysisReport(input_path=str(tmp_path), suggestions=[suggestion])

        result = execute_suggestion(report, 7)

        assert result is suggestion
        assert report.suggestions[0].status == SuggestionStatus.DONE

    def test_unknown_id_raises_value_error(self, tmp_path):
        report = AnalysisReport(input_path=str(tmp_path), suggestions=[])

        with pytest.raises(ValueError):
            execute_suggestion(report, 999)


class TestExecuteTimeoutAndOutputCaps:
    def test_blocking_read_is_killed_after_timeout(self, tmp_path):
        fifo_path = str(tmp_path / "blocking.fifo")
        os.mkfifo(fifo_path)

        original_timeout = execute_mod.TIMEOUT_SECONDS
        execute_mod.TIMEOUT_SECONDS = 1
        try:
            s = make_suggestion("strings", fifo_path)
            start = time.time()
            _execute(s)
            elapsed = time.time() - start
        finally:
            execute_mod.TIMEOUT_SECONDS = original_timeout

        assert s.status == SuggestionStatus.FAILED
        assert s.result.timed_out is True
        assert elapsed < 5  # didn't hang past the shortened timeout

    def test_large_output_spills_to_disk_with_truncated_inline_copy(self, tmp_path):
        target = tmp_path / "big.bin"
        target.write_bytes((b"abcdefghij" * 1000) + b"\x00" + (b"klmnopqrst" * 1000))

        original_cap = execute_mod.MAX_INLINE_OUTPUT_BYTES
        execute_mod.MAX_INLINE_OUTPUT_BYTES = 100
        try:
            s = make_suggestion("strings", str(target))
            _execute(s)
        finally:
            execute_mod.MAX_INLINE_OUTPUT_BYTES = original_cap

        assert s.status == SuggestionStatus.DONE
        assert s.result.stdout_truncated is True
        assert s.result.stdout_file is not None
        assert os.path.getsize(s.result.stdout_file) > len(s.result.stdout)

        os.remove(s.result.stdout_file)