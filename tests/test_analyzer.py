# test_analyzer.py

from __future__ import annotations
import os
import sys
import pytest
from forensics_copilot.analyzer import analyze
from tests.fixtures import write_minimal_png, write_minimal_jpeg, write_zip_with_files, write_password_protected_zip


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

@pytest.fixture
def tmp_sample_dir(tmp_path):
    return tmp_path


class TestFileIdentification:
    def test_extension_mismatch_detected(self, tmp_sample_dir):
        fake_jpg = tmp_sample_dir / "fake.jpg"
        fake_jpg.write_text("You Found The Flag!")
        report, temp_dirs = analyze(str(fake_jpg))

        assert len(report.detected_files) == 1
        f = report.detected_files[0]
        assert f.category == "text"
        assert f.extension_mismatch is True

    def test_matching_extension_not_flagged(self, tmp_sample_dir):
        png_path = tmp_sample_dir / "real.png"
        write_minimal_png(str(png_path))
        report, temp_dirs = analyze(str(png_path))

        f = report.detected_files[0]
        assert f.category == "image"
        assert f.extension_mismatch is False


class TestAnomalyDetection:
    def test_png_trailing_data_detected(self, tmp_sample_dir):
        png_path = tmp_sample_dir / "hidden.png"
        write_minimal_png(str(png_path), trailing_data=b"SECRET_FLAG_DATA")

        report, temp_dirs = analyze(str(png_path))

        f = report.detected_files[0]
        assert len(f.anomalies) == 1
        assert "16" in f.anomalies[0].description  # len(b"SECRET_FLAG_DATA") == 16
        assert f.anomalies[0].severity == "suspicious"

    def test_png_without_trailing_data_clean(self, tmp_sample_dir):
        png_path = tmp_sample_dir / "clean.png"
        write_minimal_png(str(png_path))

        report, temp_dirs = analyze(str(png_path))

        assert report.detected_files[0].anomalies == []

    def test_jpeg_trailing_data_detected(self, tmp_sample_dir):
        jpg_path = tmp_sample_dir / "hidden.jpg"
        write_minimal_jpeg(str(jpg_path), trailing_data=b"X" * 100)

        report, temp_dirs = analyze(str(jpg_path))

        f = report.detected_files[0]
        assert len(f.anomalies) == 1
        assert "100" in f.anomalies[0].description

    def test_zip_with_legit_comment_not_flagged(self, tmp_sample_dir):
        import zipfile

        zip_path = tmp_sample_dir / "with_comment.zip"
        with zipfile.ZipFile(str(zip_path), "w") as zf:
            zf.writestr("readme.txt", b"just a normal file")
            zf.comment = b"this is just a hint, not hidden data"

        report, temp_dirs = analyze(str(zip_path))

        top = next(f for f in report.detected_files if f.path == "with_comment.zip")
        assert top.anomalies == []


class TestArchiveExtraction:
    def test_simple_zip_recursion(self, tmp_sample_dir):
        zip_path = tmp_sample_dir / "simple.zip"
        write_zip_with_files(str(zip_path), {"flag.txt": b"FLAG{test}"})

        report, temp_dirs = analyze(str(zip_path))

        paths = [f.path for f in report.detected_files]
        assert "simple.zip" in paths
        assert "simple.zip/flag.txt" in paths

        flag_file = next(f for f in report.detected_files if f.path == "simple.zip/flag.txt")
        assert flag_file.category == "text"
        assert flag_file.extracted_from == "simple.zip"

    def test_nested_zip_recursion(self, tmp_sample_dir):
        inner_path = tmp_sample_dir / "inner.zip"
        write_zip_with_files(str(inner_path), {"flag.txt": b"FLAG{nested}"})

        outer_path = tmp_sample_dir / "outer.zip"
        with open(inner_path, "rb") as f:
            inner_bytes = f.read()
        write_zip_with_files(str(outer_path), {"inner.zip": inner_bytes})

        report, temp_dirs = analyze(str(outer_path))

        paths = [f.path for f in report.detected_files]
        assert "outer.zip" in paths
        assert "outer.zip/inner.zip" in paths
        assert "outer.zip/inner.zip/flag.txt" in paths

    def test_recursion_stops_at_max_depth(self, tmp_sample_dir):
        from forensics_copilot.extract import MAX_RECURSION_DEPTH

        path = tmp_sample_dir / f"layer{MAX_RECURSION_DEPTH + 1}.zip"
        write_zip_with_files(str(path), {"flag.txt": b"FLAG{deep}"})
        for i in range(MAX_RECURSION_DEPTH, 0, -1):
            inner = tmp_sample_dir / f"layer{i + 1}.zip"
            outer = tmp_sample_dir / f"layer{i}.zip"
            with open(inner, "rb") as f:
                write_zip_with_files(str(outer), {f"layer{i + 1}.zip": f.read()})

        report, temp_dirs = analyze(str(tmp_sample_dir / "layer1.zip"))

        warnings = [
            a.description
            for f in report.detected_files
            for a in f.anomalies
            if "recursion depth" in a.description.lower()
        ]
        assert len(warnings) == 1
        assert not any(f.path.endswith("flag.txt") for f in report.detected_files)

    def test_password_protected_zip_does_not_crash(self, tmp_sample_dir):
        zip_path = tmp_sample_dir / "protected.zip"
        write_password_protected_zip(str(zip_path), "secret.txt", b"hidden", "pass123")

        report, temp_dirs = analyze(str(zip_path))

        f = report.detected_files[0]
        assert f.category == "archive"
        assert len(report.detected_files) == 1
        assert any("password protected" in a.description for a in f.anomalies)

    def test_extracted_temp_dirs_remain_on_success(self, tmp_sample_dir):
        zip_path = tmp_sample_dir / "simple.zip"
        write_zip_with_files(str(zip_path), {"flag.txt": b"FLAG{still_here}"})

        report, temp_dirs = analyze(str(zip_path))

        assert len(temp_dirs) >= 1
        found = False
        for d in temp_dirs:
            assert os.path.isdir(d)
            for _root, _dirs, files in os.walk(d):
                if "flag.txt" in files:
                    found = True
        assert found, "flag.txt extracted into temp_dirs should actually exist on disk"


class TestDirectoryInput:
    def test_analyze_directory_of_files(self, tmp_sample_dir):
        write_minimal_png(str(tmp_sample_dir / "a.png"))
        (tmp_sample_dir / "b.txt").write_text("hello")

        report, temp_dirs = analyze(str(tmp_sample_dir))

        paths = {f.path for f in report.detected_files}
        assert paths == {"a.png", "b.txt"}


class TestSuggestions:
    def test_suggestions_generated_for_each_file(self, tmp_sample_dir):
        png_path = tmp_sample_dir / "test.png"
        write_minimal_png(str(png_path))

        report, temp_dirs = analyze(str(png_path))

        assert len(report.suggestions) > 0
        assert all(s.target_file == "test.png" for s in report.suggestions)

    def test_anomaly_bumps_priority_to_top(self, tmp_sample_dir):
        png_path = tmp_sample_dir / "test.png"
        write_minimal_png(str(png_path), trailing_data=b"hidden")

        report, temp_dirs = analyze(str(png_path))

        assert report.suggestions[0].priority == 1
        assert "anomaly" in report.suggestions[0].action.lower()

    def test_extension_mismatch_is_top_priority(self, tmp_sample_dir):
        fake = tmp_sample_dir / "fake.pdf"
        fake.write_text("not a real pdf")

        report, temp_dirs = analyze(str(fake))

        assert report.suggestions[0].priority == 1
        assert "extension" in report.suggestions[0].action.lower()

    def test_anomaly_with_trailing_data_gets_binwalk_hint(self, tmp_sample_dir):
        png_path = tmp_sample_dir / "test.png"
        write_minimal_png(str(png_path), trailing_data=b"hidden")

        report, temp_dirs = analyze(str(png_path))

        anomaly_suggestion = next(
            s for s in report.suggestions if "anomaly" in s.action.lower()
        )
        assert anomaly_suggestion.tool_hint == "binwalk"

class TestFlagScanning:
    def test_default_pattern_detected_in_text_file(self, tmp_sample_dir):
        path = tmp_sample_dir / "notes.txt"
        path.write_text("here is the answer: flag{default_pattern_hit}")

        report, temp_dirs = analyze(str(path))

        f = report.detected_files[0]
        assert len(f.flag_matches) == 1
        assert f.flag_matches[0].matched_text == "flag{default_pattern_hit}"
        assert f.flag_matches[0].pattern_name == "flag{}"

    def test_flag_scanned_in_raw_bytes_not_just_text_category(self, tmp_sample_dir):
        # Trailing data appended after a PNG's IEND is not valid PNG and the
        # file is still categorized as "image", not "text" — the scanner
        # must still catch a flag hidden in there.
        png_path = tmp_sample_dir / "hidden.png"
        from tests.fixtures import write_minimal_png
        write_minimal_png(str(png_path), trailing_data=b"ctf{hidden_in_trailing_bytes}")

        report, temp_dirs = analyze(str(png_path))

        f = report.detected_files[0]
        assert f.category == "image"
        assert any(fm.matched_text == "ctf{hidden_in_trailing_bytes}" for fm in f.flag_matches)

    def test_flag_found_inside_nested_archive(self, tmp_sample_dir):
        from tests.fixtures import write_zip_with_files
        zip_path = tmp_sample_dir / "simple.zip"
        write_zip_with_files(str(zip_path), {"flag.txt": b"FLAG{nested_inside_zip}"})

        report, temp_dirs = analyze(str(zip_path))

        nested = next(f for f in report.detected_files if f.path == "simple.zip/flag.txt")
        assert nested.flag_matches[0].matched_text == "FLAG{nested_inside_zip}"

    def test_no_match_means_empty_list(self, tmp_sample_dir):
        path = tmp_sample_dir / "boring.txt"
        path.write_text("nothing interesting here")

        report, temp_dirs = analyze(str(path))

        assert report.detected_files[0].flag_matches == []

    def test_custom_pattern_supported(self, tmp_sample_dir):
        path = tmp_sample_dir / "weird.bin"
        path.write_bytes(b"noise MYCTF{custom_format_only} noise")

        report, temp_dirs = analyze(
            str(path),
            custom_flag_patterns=[("myctf", r"MYCTF\{[^}]{1,300}\}")],
        )

        f = report.detected_files[0]
        names = {fm.pattern_name for fm in f.flag_matches}
        assert "myctf" in names

    def test_invalid_custom_pattern_does_not_crash(self, tmp_sample_dir):
        path = tmp_sample_dir / "notes.txt"
        path.write_text("flag{still_found_via_default}")

        # "(" with no closing paren is an invalid regex — should be skipped,
        # not raise.
        report, temp_dirs = analyze(
            str(path),
            custom_flag_patterns=[("broken", r"(unclosed")],
        )

        f = report.detected_files[0]
        assert any(fm.matched_text == "flag{still_found_via_default}" for fm in f.flag_matches)

    def test_flag_match_generates_top_priority_suggestion(self, tmp_sample_dir):
        path = tmp_sample_dir / "notes.txt"
        path.write_text("flag{priority_zero}")

        report, temp_dirs = analyze(str(path))

        assert report.suggestions[0].priority == 0
        assert "flag{priority_zero}" in report.suggestions[0].action