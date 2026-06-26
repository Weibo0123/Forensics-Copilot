# Forensics Copilot

A command-line assistant for CTF **forensics** challenges. To use it, users need to point it at a file or a directory. It will:

- Identify the real file type (not rely on the extension)
- Mark extension/MIME mismatches
- Detect trailing/appended data in PNG, JPEG and ZIP files
- Recursively extract nested archives (zip/tar/gz/bz2/xz) with a depth limit and handling of password-protected zip
- scan every file's raw bytes for flags in plain text with two built-in flag format `flag{...}` / `CTF{...}`. Users could also use custom flag formats
- Generate a prioritized list of next-step suggestions with the tools that users can use by themselves
- Optionally run those tools for you, one at a time, with yes/no per suggestion

It does not auto-solve challenges, but it lets users skip the first boring and repetitive step.

