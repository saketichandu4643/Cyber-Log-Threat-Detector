# ZIPShield — Secure ZIP File Analyzer

A beginner-friendly cybersecurity project that inspects ZIP archives before extraction. It demonstrates defensive file handling, path traversal prevention, suspicious-extension warnings, and basic archive limits.

## Features
- Upload a `.zip` archive through a browser interface.
- Review file names and compressed/uncompressed sizes.
- Flag potentially risky extensions such as `.exe`, `.bat`, `.ps1`, `.vbs`, `.js`, and `.msi`.
- Detect path traversal attempts such as `../../outside.txt`.
- Apply entry-count, total-size, per-file-size, and compression-ratio checks.
- Extract to a temporary output folder and download the result as a ZIP.

## Limitations
These checks are heuristics, not malware detection. A flagged extension is not proof of malware, and a clean report does not prove that files are safe. ZIPShield does not execute files or replace antivirus software.

## Run locally
Requires Python 3.10+.

```bash
python -m venv .venv
```

Windows:
```bash
.venv\Scripts\activate
```

macOS/Linux:
```bash
source .venv/bin/activate
```

Install and run:
```bash
pip install -r requirements.txt
streamlit run app.py
```

## Suggested tests
1. ZIP containing `notes.txt` — should have no basic heuristic warning.
2. ZIP containing `setup.exe` — should flag the extension.
3. ZIP containing `../../outside.txt` — should block extraction.
4. Oversized archive — should trigger configured limits.

Use harmless test files only. Do not execute unknown files.

## GitHub repository description
A Python defensive ZIP archive analyzer with suspicious-file warnings, path traversal protection, and safer extraction controls.

## Tech stack
Python, Streamlit, `zipfile`, `pathlib`, `tempfile`.

## License
MIT
