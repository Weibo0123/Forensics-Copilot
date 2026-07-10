# test_audio.py
from __future__ import annotations

import importlib.util
import json
import os
import struct
import wave
import pytest
import numpy as np
from forensics_copilot import execute as execute_mod
from forensics_copilot.execute import (
    _execute,
    _parse_plugin_findings,
    execute_suggestion,
    is_tool_wired,
)
from forensics_copilot.model import (
    AnalysisReport,
    DetectedFile,
    ExecutionResult,
    Finding,
    Suggestion,
    SuggestionStatus,
)
from forensics_copilot.report import render_findings


AUDIO_ANALYZER_AVAILABLE = importlib.util.find_spec("audio_analyzer") is not None

def _make_suggestion(tool_hint="audio_analyzer", target_abs_path="/tmp/fake.wav") -> Suggestion:
    return Suggestion(
        id=1,
        target_file=os.path.basename(target_abs_path),
        target_abs_path=target_abs_path,
        action="test",
        reason="test",
        tool_hint=tool_hint,
    )


def write_silent_wav(path: str, duration_s: float = 0.5, sample_rate: int = 22050) -> None:
    """Write a valid WAV file containing only silence — no signal to detect."""
    n_frames = int(duration_s * sample_rate)
    with wave.open(path, "w") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(b"\x00\x00" * n_frames)


def write_morse_wav(path: str, text: str = "SOS", sample_rate: int = 22050) -> None:
    freq = 1000.0
    dot_s = 0.08
    dash_s = dot_s * 3
    elem_gap_s = dot_s
    letter_gap_s = dot_s * 3
    word_gap_s = dot_s * 7

    MORSE_TABLE = {
        "A": ".-",   "B": "-...", "C": "-.-.", "D": "-..",
        "E": ".",    "F": "..-.", "G": "--.",  "H": "....",
        "I": "..",   "J": ".---", "K": "-.-",  "L": ".-..",
        "M": "--",   "N": "-.",   "O": "---",  "P": ".--.",
        "Q": "--.-", "R": ".-.",  "S": "...",  "T": "-",
        "U": "..-",  "V": "...-", "W": ".--",  "X": "-..-",
        "Y": "-.--", "Z": "--..",
        "0": "-----","1": ".----","2": "..---","3": "...--",
        "4": "....-","5": ".....","6": "-....","7": "--...",
        "8": "---..","9": "----.",
    }

    def tone(duration_s: float) -> np.ndarray:
        t = np.linspace(0, duration_s, int(duration_s * sample_rate), endpoint=False)
        return np.sin(2 * np.pi * freq * t)

    def silence(duration_s: float) -> np.ndarray:
        return np.zeros(int(duration_s * sample_rate))

    chunks: list[np.ndarray] = [silence(0.3)]  # leading silence to help onset detection
    words = text.upper().split()
    for w_idx, word in enumerate(words):
        for l_idx, letter in enumerate(word):
            code = MORSE_TABLE.get(letter)
            if code is None:
                continue
            for e_idx, symbol in enumerate(code):
                chunks.append(tone(dash_s if symbol == "-" else dot_s))
                if e_idx < len(code) - 1:
                    chunks.append(silence(elem_gap_s))
            if l_idx < len(word) - 1:
                chunks.append(silence(letter_gap_s))
        if w_idx < len(words) - 1:
            chunks.append(silence(word_gap_s))
    chunks.append(silence(0.3))  # trailing silence

    signal = np.concatenate(chunks)
    pcm = (signal * 32000).astype(np.int16)

    with wave.open(path, "w") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(pcm.tobytes())

class TestAudioAnalyzerWiring:
    def test_audio_analyzer_is_in_tool_commands(self):
        assert "audio_analyzer" in execute_mod._TOOL_COMMANDS

    def test_audio_analyzer_command_invokes_module_with_json_flag(self):
        cmd = execute_mod._TOOL_COMMANDS["audio_analyzer"]
        assert cmd[:3] == ["python3", "-m", "audio_analyzer.cli"]
        assert "--json" in cmd

    def test_audio_analyzer_is_in_python_module_tools(self):
        assert "audio_analyzer" in execute_mod._PYTHON_MODULE_TOOLS

    def test_audio_analyzer_is_reported_as_wired(self):
        assert is_tool_wired("audio_analyzer") is True

    def test_audio_analyzer_has_install_hint(self):
        assert "audio_analyzer" in execute_mod._INSTALL_HINTS
        hint = execute_mod._INSTALL_HINTS["audio_analyzer"]
        assert "pip" in hint.lower()

class TestAudioAnalyzerInstallCheck:
    def test_not_installed_fails_with_friendly_hint(self, tmp_path, monkeypatch):
        target = tmp_path / "audio.wav"
        write_silent_wav(str(target))

        # Simulate audio_analyzer not being installed.
        monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)

        s = _make_suggestion(target_abs_path=str(target))
        _execute(s)

        assert s.status == SuggestionStatus.FAILED
        assert s.result.error is not None
        assert "not installed" in s.result.error.lower()
        assert "pip" in s.result.error.lower()

    def test_not_installed_does_not_raise_exception(self, tmp_path, monkeypatch):
        target = tmp_path / "audio.wav"
        write_silent_wav(str(target))
        monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)

        s = _make_suggestion(target_abs_path=str(target))
        try:
            _execute(s)
        except Exception as exc:
            pytest.fail(f"_execute raised unexpectedly: {exc}")

class TestParsePluginFindings:
    def _make_result(self, payload: dict) -> ExecutionResult:
        return ExecutionResult(
            tool="audio_analyzer",
            command=[],
            returncode=0,
            stdout=json.dumps(payload),
        )

    def test_valid_finding_parsed_correctly(self):
        result = self._make_result({
            "findings": [{
                "kind": "morse_code_candidate",
                "confidence": 0.95,
                "summary": "Detected morse pattern",
                "detail": {"decoded_text": "SOS"},
                "concluded_value": "SOS",
            }]
        })
        s = _make_suggestion()
        _parse_plugin_findings(result, s, module="audio_analyzer")

        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.kind == "morse_code_candidate"
        assert f.confidence == pytest.approx(0.95)
        assert f.summary == "Detected morse pattern"
        assert f.detail == {"decoded_text": "SOS"}
        assert f.concluded_value == "SOS"

    def test_caller_fields_filled_from_suggestion_not_plugin(self):
        result = self._make_result({
            "findings": [{"kind": "x", "confidence": 0.5, "summary": "s", "detail": {}}]
        })
        s = _make_suggestion(target_abs_path="/real/path/audio.wav")
        s.target_file = "display/path/audio.wav"
        _parse_plugin_findings(result, s, module="audio_analyzer")

        f = result.findings[0]
        assert f.module == "audio_analyzer"
        assert f.target_file == "display/path/audio.wav"
        assert f.target_abs_path == "/real/path/audio.wav"

    def test_empty_findings_list_produces_zero_findings(self):
        result = self._make_result({"findings": []})
        s = _make_suggestion()
        _parse_plugin_findings(result, s, module="audio_analyzer")

        assert result.findings == []

    def test_concluded_value_none_when_absent_from_json(self):
        result = self._make_result({
            "findings": [{"kind": "x", "confidence": 0.5, "summary": "s", "detail": {}}]
        })
        s = _make_suggestion()
        _parse_plugin_findings(result, s, module="audio_analyzer")

        assert result.findings[0].concluded_value is None

    def test_multiple_findings_all_parsed(self):
        result = self._make_result({
            "findings": [
                {"kind": "a", "confidence": 0.8, "summary": "first",  "detail": {}},
                {"kind": "b", "confidence": 0.5, "summary": "second", "detail": {}},
            ]
        })
        s = _make_suggestion()
        _parse_plugin_findings(result, s, module="audio_analyzer")

        assert len(result.findings) == 2
        assert result.findings[0].kind == "a"
        assert result.findings[1].kind == "b"

    def test_malformed_json_does_not_crash(self):
        result = ExecutionResult(tool="audio_analyzer", command=[], returncode=0, stdout="not json {{{{")
        s = _make_suggestion()
        try:
            _parse_plugin_findings(result, s, module="audio_analyzer")
        except Exception as exc:
            pytest.fail(f"Should not raise on malformed JSON: {exc}")
        assert result.findings == []

    def test_missing_keys_in_finding_do_not_crash(self):
        result = self._make_result({"findings": [{}]})
        s = _make_suggestion()
        try:
            _parse_plugin_findings(result, s, module="audio_analyzer")
        except Exception as exc:
            pytest.fail(f"Should not raise on partial finding dict: {exc}")

    def test_raw_stdout_still_accessible_after_successful_parse(self):
        payload = {"findings": [{"kind": "x", "confidence": 1.0, "summary": "s", "detail": {}}]}
        raw = json.dumps(payload)
        result = ExecutionResult(tool="audio_analyzer", command=[], returncode=0, stdout=raw)
        s = _make_suggestion()
        _parse_plugin_findings(result, s, module="audio_analyzer")
        assert result.stdout == raw

class TestRenderFindings:
    def _finding(self, **kwargs) -> Finding:
        defaults = dict(
            module="audio_analyzer",
            kind="morse_code_candidate",
            confidence=0.9,
            summary="Detected morse pattern",
            detail={},
            target_file="audio.wav",
            target_abs_path="/tmp/audio.wav",
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_empty_list_returns_no_findings_message(self):
        out = render_findings([])
        assert "no findings" in out.lower()

    def test_kind_appears_in_output(self):
        out = render_findings([self._finding(kind="morse_code_candidate")])
        assert "morse_code_candidate" in out

    def test_confidence_appears_in_output(self):
        out = render_findings([self._finding(confidence=0.75)])
        assert "0.75" in out

    def test_summary_appears_in_output(self):
        out = render_findings([self._finding(summary="found a pattern")])
        assert "found a pattern" in out

    def test_concluded_value_shown_when_present(self):
        out = render_findings([self._finding(concluded_value="SOS")])
        assert "SOS" in out
        assert "concluded" in out.lower()

    def test_concluded_value_not_shown_when_none(self):
        out = render_findings([self._finding(concluded_value=None)])
        assert "concluded" not in out.lower()

    def test_high_confidence_bar_mostly_filled(self):
        out = render_findings([self._finding(confidence=1.0)])
        # 10 filled blocks, 0 empty
        assert "█" * 10 in out
        assert "░" not in out

    def test_zero_confidence_bar_empty(self):
        out = render_findings([self._finding(confidence=0.0)])
        assert "░" * 10 in out
        assert "█" not in out

    def test_multiple_findings_all_rendered(self):
        findings = [
            self._finding(kind="first",  summary="alpha"),
            self._finding(kind="second", summary="beta"),
        ]
        out = render_findings(findings)
        assert "first" in out
        assert "second" in out
        assert "alpha" in out
        assert "beta" in out

@pytest.mark.skipif(not AUDIO_ANALYZER_AVAILABLE, reason="audio_analyzer not installed")
class TestAudioAnalyzerEndToEnd:
    def test_runs_on_silent_wav_status_done(self, tmp_path):
        wav = tmp_path / "silent.wav"
        write_silent_wav(str(wav))

        s = _make_suggestion(target_abs_path=str(wav))
        _execute(s)

        assert s.status == SuggestionStatus.DONE
        assert s.result.error is None

    def test_silent_wav_has_no_findings(self, tmp_path):
        wav = tmp_path / "silent.wav"
        write_silent_wav(str(wav))

        s = _make_suggestion(target_abs_path=str(wav))
        _execute(s)

        assert s.result.findings == []

    def test_morse_wav_produces_finding(self, tmp_path):
        wav = tmp_path / "morse.wav"
        write_morse_wav(str(wav), text="SOS")

        s = _make_suggestion(target_abs_path=str(wav))
        _execute(s)

        assert s.status == SuggestionStatus.DONE
        assert len(s.result.findings) >= 1

    def test_morse_wav_finding_has_correct_fields(self, tmp_path):
        wav = tmp_path / "morse.wav"
        write_morse_wav(str(wav), text="SOS")

        s = _make_suggestion(target_abs_path=str(wav))
        _execute(s)

        f = s.result.findings[0]
        assert f.module == "audio_analyzer"
        assert f.kind == "morse_code_candidate"
        assert 0.0 <= f.confidence <= 1.0
        assert f.summary != ""
        assert f.target_file == "morse.wav"
        assert f.target_abs_path == str(wav)

    def test_morse_wav_decodes_sos(self, tmp_path):
        wav = tmp_path / "morse.wav"
        write_morse_wav(str(wav), text="SOS")

        s = _make_suggestion(target_abs_path=str(wav))
        _execute(s)

        decoded = s.result.findings[0].concluded_value
        assert decoded is not None
        assert "SOS" in decoded.upper()

    def test_garbage_file_fails_gracefully(self, tmp_path):
        garbage = tmp_path / "garbage.wav"
        garbage.write_bytes(os.urandom(128))

        s = _make_suggestion(target_abs_path=str(garbage))
        _execute(s)  # must not raise

        assert s.status == SuggestionStatus.FAILED
        assert s.result.findings == []

    def test_empty_file_fails_gracefully(self, tmp_path):
        empty = tmp_path / "empty.wav"
        empty.write_bytes(b"")

        s = _make_suggestion(target_abs_path=str(empty))
        _execute(s)  # must not raise

        assert s.status == SuggestionStatus.FAILED
        assert s.result.findings == []

    def test_execute_suggestion_by_id_wires_through(self, tmp_path):
        wav = tmp_path / "silent.wav"
        write_silent_wav(str(wav))

        s = _make_suggestion(target_abs_path=str(wav))
        s.id = 42
        report = AnalysisReport(input_path=str(wav), suggestions=[s])

        result = execute_suggestion(report, 42)

        assert result is s
        assert s.status == SuggestionStatus.DONE

class TestAudioSuggestions:
    def _audio_file(self, tmp_path) -> DetectedFile:
        wav = tmp_path / "audio.wav"
        write_silent_wav(str(wav))
        return DetectedFile(
            path="audio.wav",
            abs_path=str(wav),
            size_bytes=wav.stat().st_size,
            declared_ext=".wav",
            detected_mime="audio/x-wav",
            detected_type_label="WAV audio",
            category="audio",
        )

    def _suggestions_for(self, tmp_path):
        from forensics_copilot.analyzer import analyze
        wav = tmp_path / "audio.wav"
        write_silent_wav(str(wav))
        report, _ = analyze(str(wav))
        return report.suggestions

    def test_audio_file_gets_audio_analyzer_suggestion(self, tmp_path):
        suggestions = self._suggestions_for(tmp_path)
        hints = {s.tool_hint for s in suggestions}
        assert "audio_analyzer" in hints

    def test_audio_analyzer_suggestion_is_high_priority(self, tmp_path):
        suggestions = self._suggestions_for(tmp_path)
        aa = next(s for s in suggestions if s.tool_hint == "audio_analyzer")
        assert aa.priority == 1

    def test_audio_analyzer_suggestion_is_reported_as_wired(self, tmp_path):
        suggestions = self._suggestions_for(tmp_path)
        aa = next(s for s in suggestions if s.tool_hint == "audio_analyzer")
        assert is_tool_wired(aa.tool_hint)

    def test_audio_file_still_gets_spectrogram_manual_suggestion(self, tmp_path):
        suggestions = self._suggestions_for(tmp_path)
        # Sonic Visualiser / Audacity should remain as a lower-priority manual hint.
        assert any("Sonic Visualiser" in (s.tool_hint or "") for s in suggestions)

    def test_audio_file_still_gets_exiftool_suggestion(self, tmp_path):
        suggestions = self._suggestions_for(tmp_path)
        hints = {s.tool_hint for s in suggestions}
        assert "exiftool" in hints

    def test_non_audio_file_does_not_get_audio_analyzer_suggestion(self, tmp_path):
        from forensics_copilot.analyzer import analyze
        from tests.fixtures import write_minimal_png
        png = tmp_path / "image.png"
        write_minimal_png(str(png))
        report, _ = analyze(str(png))
        hints = {s.tool_hint for s in report.suggestions}
        assert "audio_analyzer" not in hints