# vst-scanner-and-deduplicator

Poetry-based Python scanner for Windows VST plugins.

This project is based on the original PowerShell scanner and extends it by:

- scanning known VST2 (`.dll`) and VST3 (`.vst3`) paths,
- extracting plugin identity as **vendor + plugin name** for dedupe,
- extracting PE version string metadata (product/company/description),
- supporting a fast default scan and optional deep binary validation,
- outputting duplicate and unique reports.

Default (shallow) mode uses streaming ASCII string extraction from binaries for much faster identity scans.

## Requirements

- Windows
- Python 3.10+
- Poetry

## Install

```powershell
poetry install
```

## Run

Default scan using built-in paths:

```powershell
poetry run vst-scan
```

Verbose progress output (recommended for first run):

```powershell
poetry run vst-scan --verbose --progress-every 25
```

Deep scan (slower, stricter VST2 validation via exports + ctypes):

```powershell
poetry run vst-scan --verbose --deep --progress-every 25
```

Quick debug run (only first 100 DLLs):

```powershell
poetry run vst-scan --verbose --max-files 100 --output-dir ".\reports"
```

Custom paths:

```powershell
poetry run vst-scan \
	--vst2-path "C:\Program Files\VSTPlugins" \
	--vst2-path "D:\Audio\VST2" \
	--vst3-path "C:\Program Files\Common Files\VST3" \
	--output-dir ".\reports"
```

## Output

The scanner writes:

- `VST2-Duplicates-YYYY.MM.DD.txt` (VST2 plugins that also have VST3)
- `VST2-Unique-YYYY.MM.DD.txt` (VST2 plugins without VST3 match)
- `VST-Scan-YYYY.MM.DD.json` (full structured details including exports and metadata)
- `remove-vst2-duplicates.ps1` (PowerShell script to remove duplicate VST2 files)
- `VST-Library-YYYY.MM.DD.csv` (Excel-friendly plugin library export)
- `vst-library-cache.sqlite` (incremental cache keyed by full path + modified date)

Deduplication key is `vendor::plugin` in normalized lowercase form.

## Incremental Library Index

`vst-scan` now builds a cached library index each run:

- On first run, all discovered plugins are scanned and cached.
- On subsequent runs, unchanged files are reused from SQLite cache.
- Changed or new files are rescanned and cache is updated.

Useful options:

```powershell
poetry run vst-scan --cache-db "vst-library-cache.sqlite" --library-csv "VST-Library.csv"
```
