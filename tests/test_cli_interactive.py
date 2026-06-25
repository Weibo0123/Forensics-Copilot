# test_cli_interactive.py

from __future__ import annotations
from forensics_copilot.cli import _prompt_and_execute
from forensics_copilot.model import AnalysisReport, Suggestion, SuggestionStatus


def make_suggestion(tool_hint, target_abs_path, **overrides) -> Suggestion:
    defaults = dict(
        id=overrides.pop("id", 1),
        target_file=overrides.pop("target_file", "f.txt"),
        target_abs_path=target_abs_path,
        action="test action",
        reason="test reason",
        tool_hint=tool_hint,
    )
    defaults.update(overrides)
    return Suggestion(**defaults)


def fake_input(*answers):
    it = iter(answers)
    def _input(prompt):
        return next(it)
    return _input


class TestPromptAndExecute:
    def test_yes_runs_the_tool(self, tmp_path):
        target = tmp_path / "hello.txt"
        target.write_text("hello")
        s = make_suggestion("file", str(target), id=1)
        report = AnalysisReport(input_path=str(tmp_path), suggestions=[s])

        _prompt_and_execute(report, input_fn=fake_input("y"))

        assert s.status == SuggestionStatus.DONE
        assert s.result is not None

    def test_no_marks_rejected_without_running(self, tmp_path):
        target = tmp_path / "hello.txt"
        target.write_text("hello")
        s = make_suggestion("file", str(target), id=1)
        report = AnalysisReport(input_path=str(tmp_path), suggestions=[s])

        _prompt_and_execute(report, input_fn=fake_input("n"))

        assert s.status == SuggestionStatus.REJECTED
        assert s.result is None

    def test_quit_stops_and_leaves_rest_pending(self, tmp_path):
        t1 = tmp_path / "a.txt"; t1.write_text("a")
        t2 = tmp_path / "b.txt"; t2.write_text("b")
        s1 = make_suggestion("file", str(t1), id=1, target_file="a.txt")
        s2 = make_suggestion("file", str(t2), id=2, target_file="b.txt")
        report = AnalysisReport(input_path=str(tmp_path), suggestions=[s1, s2])

        _prompt_and_execute(report, input_fn=fake_input("q"))

        assert s1.status == SuggestionStatus.PENDING
        assert s2.status == SuggestionStatus.PENDING

    def test_eof_on_stdin_stops_gracefully_without_raising(self, tmp_path):
        target = tmp_path / "hello.txt"
        target.write_text("hello")
        s = make_suggestion("file", str(target), id=1)
        report = AnalysisReport(input_path=str(tmp_path), suggestions=[s])

        def raises_eof(prompt):
            raise EOFError

        _prompt_and_execute(report, input_fn=raises_eof)  # must not raise

        assert s.status == SuggestionStatus.PENDING

    def test_suggestions_without_wired_tool_are_never_prompted(self, tmp_path):
        target = tmp_path / "hello.txt"
        target.write_text("hello")
        flag_suggestion = make_suggestion(None, str(target), id=1)
        unwired_suggestion = make_suggestion("binwalk", str(target), id=2)
        report = AnalysisReport(input_path=str(tmp_path), suggestions=[flag_suggestion, unwired_suggestion])

        def fail_if_called(prompt):
            raise AssertionError("should never prompt for a non-runnable suggestion")

        _prompt_and_execute(report, input_fn=fail_if_called)  # must not call input_fn at all

        assert flag_suggestion.status == SuggestionStatus.PENDING
        assert unwired_suggestion.status == SuggestionStatus.PENDING

    def test_already_non_pending_suggestion_is_not_reprompted(self, tmp_path):
        target = tmp_path / "hello.txt"
        target.write_text("hello")
        s = make_suggestion("file", str(target), id=1)
        s.status = SuggestionStatus.DONE
        report = AnalysisReport(input_path=str(tmp_path), suggestions=[s])

        def fail_if_called(prompt):
            raise AssertionError("should not re-prompt an already-resolved suggestion")

        _prompt_and_execute(report, input_fn=fail_if_called)