import os
import zipfile
import tempfile
from pathlib import Path, PurePosixPath
import streamlit as st

APP_NAME = "ZIPShield"
RISKY_EXTENSIONS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".ps1",
                    ".vbs", ".js", ".hta", ".msi", ".jar", ".lnk"}
MAX_FILES = 1000
MAX_TOTAL_SIZE = 100 * 1024 * 1024
MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_RATIO = 100

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")
st.title("🛡️ ZIPShield")
st.write("Inspect ZIP archives before extracting them.")
st.warning("This uses basic heuristics, not antivirus scanning. A warning is not proof of malware, and a clean scan does not guarantee safety. Never run unknown files.")

def scan_zip(zf):
    rows, warnings = [], []
    infos = zf.infolist()
    total = sum(i.file_size for i in infos if not i.is_dir())
    if len(infos) > MAX_FILES:
        warnings.append(f"Archive has {len(infos)} entries; limit is {MAX_FILES}.")
    if total > MAX_TOTAL_SIZE:
        warnings.append("Archive exceeds the total uncompressed-size limit.")

    for info in infos:
        name = info.filename
        normalized = name.replace("\\\\", "/")
        rel = PurePosixPath(normalized)
        issues = []
        if rel.is_absolute() or normalized.startswith("/") or ".." in rel.parts:
            issues.append("Unsafe path / possible path traversal")
        ext = Path(rel.name).suffix.lower()
        if ext in RISKY_EXTENSIONS:
            issues.append(f"Potentially risky extension: {ext}")
        if not info.is_dir() and info.file_size > MAX_FILE_SIZE:
            issues.append("File exceeds per-file size limit")
        if info.file_size and info.compress_size == 0:
            issues.append("Suspicious compression metadata")
        elif info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
            issues.append("High compression ratio / possible ZIP-bomb indicator")
        if issues:
            warnings.append(f"{name}: " + "; ".join(issues))
        rows.append({"File": name, "Compressed bytes": info.compress_size,
                     "Uncompressed bytes": info.file_size,
                     "Status": "Review" if issues else "No basic warning",
                     "Findings": "; ".join(issues) if issues else "No heuristic flags"})
    return rows, warnings, total, len(infos)

def safe_extract(zf, destination):
    root = Path(destination).resolve()
    extracted = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        normalized = info.filename.replace("\\\\", "/")
        rel = PurePosixPath(normalized)
        if rel.is_absolute() or ".." in rel.parts or (rel.parts and ":" in rel.parts[0]):
            raise ValueError(f"Blocked unsafe path: {info.filename}")
        target = (root / Path(*rel.parts)).resolve()
        if target != root and root not in target.parents:
            raise ValueError(f"Blocked path escaping output folder: {info.filename}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "xb") as dst:
            while True:
                chunk = src.read(65536)
                if not chunk:
                    break
                dst.write(chunk)
        extracted.append(str(target.relative_to(root)))
    return extracted

uploaded = st.file_uploader("Select a ZIP file", type=["zip"])
if uploaded:
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(uploaded.getvalue())
            temp_path = tmp.name
        with zipfile.ZipFile(temp_path) as zf:
            rows, warnings, total, count = scan_zip(zf)
            a, b, c = st.columns(3)
            a.metric("Entries", count)
            b.metric("Uncompressed size", f"{total / (1024*1024):.2f} MB")
            c.metric("Warnings", len(warnings))
            st.dataframe(rows, use_container_width=True, hide_index=True)
            if warnings:
                st.error("Review these warnings before extraction.")
                for warning in warnings:
                    st.write("- " + warning)
            else:
                st.success("No basic heuristic warnings found.")

            confirm = st.checkbox("I understand this scan cannot guarantee that files are safe.")
            if st.button("Extract safely", type="primary", disabled=not confirm):
                has_unsafe = any("Unsafe path" in r["Findings"] for r in rows)
                too_large = count > MAX_FILES or total > MAX_TOTAL_SIZE
                if has_unsafe:
                    st.error("Extraction blocked because unsafe archive paths were detected.")
                elif too_large:
                    st.error("Extraction blocked because archive limits were exceeded.")
                else:
                    with tempfile.TemporaryDirectory() as outdir:
                        extracted = safe_extract(zf, outdir)
                        bundle = os.path.join(outdir, "extracted_files.zip")
                        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as output:
                            for rel_name in extracted:
                                output.write(os.path.join(outdir, rel_name), arcname=rel_name)
                        with open(bundle, "rb") as handle:
                            st.download_button("Download extracted files as ZIP",
                                data=handle.read(), file_name="zipshield_extracted_files.zip",
                                mime="application/zip")
                        st.success(f"Prepared {len(extracted)} files.")
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError) as exc:
        st.error(f"Could not safely process this archive: {exc}")
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

st.caption("Educational defensive security project • Python + Streamlit")
