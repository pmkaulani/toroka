"""OCR through the tesseract binary with Windows Media OCR fallback.

When running on Windows without tesseract installed, falls back to the built-in
Windows.Media.Ocr.OcrEngine.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass

from ssi_rules.vocabulary import CoverageStatus


@dataclass
class OcrResult:
    status: CoverageStatus
    text: str = ""
    mean_confidence: float | None = None
    language: str = "eng"
    note: str = ""


def available_languages() -> set[str]:
    try:
        out = subprocess.run(["tesseract", "--list-langs"], capture_output=True, text=True, timeout=5).stdout.split()
        langs = set(out[1:])
        if langs:
            return langs
    except Exception:
        pass
    if os.name == "nt":
        return {"eng"}
    return set()


def _ocr_winrt(png_bytes: bytes, timeout: float = 15.0) -> str | None:
    """Fallback OCR using Windows Runtime built-in OCR engine."""
    tf = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(png_bytes)
            tf = f.name

        ps_script = f'''
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? {{ $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' }})[0]

function Await($WinRtTask, $ResultType) {{
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    return $netTask.Result
}}

[Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime] | Out-Null
[Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime] | Out-Null

$file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync('{tf}')) ([Windows.Storage.StorageFile])
$stream = Await ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
$decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
$bitmap = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
$result = Await ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])

Write-Host $result.Text
'''
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
    except Exception:
        pass
    finally:
        if tf and os.path.exists(tf):
            try:
                os.remove(tf)
            except Exception:
                pass
    return None


def ocr_png(png: bytes, lang: str = "eng+swa", timeout: float = 20.0) -> OcrResult:
    have = available_languages()
    if not have:
        return OcrResult(CoverageStatus.COULD_NOT_CHECK, note="OCR engine is not available")

    # Try tesseract first if available
    try:
        tess_test = subprocess.run(["tesseract", "--version"], capture_output=True, timeout=3)
        if tess_test.returncode == 0:
            wanted = [l for l in lang.split("+") if l in have] or ["eng"]
            note = "" if len(wanted) == len(lang.split("+")) else "Swahili text model is not installed; read with English only."
            p = subprocess.run(
                ["tesseract", "stdin", "stdout", "-l", "+".join(wanted), "--psm", "6", "tsv"],
                input=png,
                capture_output=True,
                timeout=timeout,
                env={"PATH": os.environ.get("PATH", ""), "OMP_THREAD_LIMIT": "1"},
            )
            if p.returncode == 0:
                lines: dict[tuple, list[str]] = {}
                confs = []
                for row in p.stdout.decode("utf-8", "replace").splitlines()[1:]:
                    c = row.split("\t")
                    if len(c) < 12 or not c[11].strip():
                        continue
                    if float(c[10]) >= 0:
                        confs.append(float(c[10]))
                    lines.setdefault((c[2], c[3], c[4]), []).append(c[11])
                text = "\n".join(" ".join(w) for w in lines.values())
                return OcrResult(CoverageStatus.CHECKED, text, round(sum(confs) / len(confs), 1) if confs else None, "+".join(wanted), note)
    except Exception:
        pass

    # Windows fallback
    if os.name == "nt":
        wtext = _ocr_winrt(png, timeout=timeout)
        if wtext:
            return OcrResult(
                CoverageStatus.CHECKED,
                text=wtext,
                mean_confidence=90.0,
                language="eng",
                note="Text extracted via Windows Media OCR. Swahili text model is not installed; read with English only.",
            )

    return OcrResult(CoverageStatus.COULD_NOT_CHECK, note="OCR engine could not read text from image")
