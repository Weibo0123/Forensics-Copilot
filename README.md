# Forensics Copilot

A command-line assistant for CTF **forensics** challenges. To use it, users need to point it at a file or a directory. It will:

- Identify the real file type (not rely on the extension)
- Mark extension/MIME mismatches
- Detect trailing/appended data in PNG, JPEG and ZIP files
- Recursively extract nested archives (zip/tar/gz/bz2/xz) with a depth limit and handling of password-protected zip
- scan every file's raw bytes for flags in plain text with two built-in flag format `flag{...}` / `CTF{...}`. Users could also use custom flag formats
- Generate a prioritized list of next-step suggestions with the tools that users can use by themselves
- Optionally run those tools for you, one at a time, with yes/no per suggestion

It does not auto-solve challenges, but it lets users skip some boring and repetitive steps.

---

## Install

Requires Python 3.9+.

```bash
python -m venv venv
source  venv/bin/activate
pip install python-magic
pip install forensics-copilot==0.1.0
```

This installs the 'forensics-copilot' command.

### System Dependencies

The core analysis (file identification, anomaly detection, archive extraction, flag scanning) is pure Python and has no system dependencies beyond "python-magic" (installed automatically)
which itself depends on "libmagic."
To install:

```bash
# Debian/Ubuntu
apt install libmagic1
# macOS
brew install libmagic
```

The `--interactive` flag can additionally run a small set of external tools (see [Tools used by --interactive](#tools-used-by---interactive) below). None of them are required just to get a report. They're only needed if you want to execute the suggestions Forensics Copilot generates.

---

## Quick Start

```bash
forsensic-copilot path/to/challenge_file
```

This prints a report: every file found (including everything recursively extracted from nested archives), any anomalies detected and a prioritized suggestion list.

```bash
forensics-copilot path/to/challenge_folder/
```

Works the same way on a directory. Every file inside is analyzed.

---

## CLI Parameters

| Parameters                    | Description                                                                                                                                                                                                                                                                                  |
|-------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--json OUT_FILE`             | Save the full report (including any results from `--interactive`) as JSON to `OUT_FILE`.                                                                                                                                                                                                     |
| `--flag-pattern [NAME=]REGEX` | Add a custom flag-format regex, in addition to the built-in `flag{}` / `ctf{}` patterns. Matched against raw bytes, case-insensitive. Repeatable pass it multiple times for multiple custom formats. The `NAME=` prefix is optional and only affects how the match is labeled in the report. |
| `--interactive`               | After the report, ask once per suggestion whether to run its tool (`y`/`n`/`q`). Nothing executes without explicit per-suggestion confirmation. There's no "run everything" mode.                                                                                                            |


### Custom Flag Formats

Different CTFs use different flag formats. If your challenge uses something other than 'flag{...}' or 'ctf{...}', add it with the parameter:

```bash
forensics-copilot challenge.zip --flag-pattern 'myctf=MYCTF\{[^}]{1,300}\}'
```

You can repeat '--flag-pattern' for multiple formats. If you skip the 'NAME=' prefix, it will be auto-labeled 'custom1', 'custom2'.

___

## Tools Used By '--interactive'

| Tool | Used for | Install (Debian/Ubuntu) | Install (macOS) |
|---|---|---|---|
| `file` | Confirming actual file type when the extension looks wrong | `apt install file` | `brew install file` |
| `strings` | Pulling readable text out of binary files | `apt install binutils` | `brew install binutils` |
| `exiftool` | Reading image/file metadata | `apt install libimage-exiftool-perl` | `brew install exiftool` |
| `xxd` | Raw hex dump — checking magic bytes / header structure | `apt install xxd` | ships by default |
| `zipinfo` | Listing a ZIP's contents without extracting it | `apt install unzip` | `brew install unzip` |
| `pngcheck` | Validating PNG structure chunk-by-chunk | `apt install pngcheck` | `brew install pngcheck` |
| `ent` | Byte-level entropy — spotting likely encrypted/compressed/hidden data | `apt install ent` | `brew install ent` |

## Limitations 
- Only a first batch of read-only tools is wired up for execution (see table above) — more will be added incrementally.
- No automated decision loop (e.g. "this didn't find anything, try the next tool automatically") — every execution is a deliberate, individual choice, by design for now.
