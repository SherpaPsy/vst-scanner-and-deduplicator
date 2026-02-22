from __future__ import annotations

import argparse
from pathlib import Path

from .scanner import (
    DEFAULT_VST2_PATHS,
    DEFAULT_VST3_PATH,
    build_library_index,
    save_reports,
    scan_plugins,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vst-scan",
        description="Scan Windows VST2/VST3 folders and detect duplicates by vendor + plugin name.",
    )
    parser.add_argument(
        "--vst2-path",
        action="append",
        default=None,
        help="Add a VST2 folder path to scan. Can be repeated.",
    )
    parser.add_argument(
        "--vst3-path",
        default=DEFAULT_VST3_PATH,
        help="VST3 folder path to scan.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path.cwd() / "reports"),
        help="Folder where report files will be written.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print progress/debug output while scanning.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=50,
        help="Emit progress every N discovered/inspected files.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Debug mode: only inspect the first N discovered VST2 DLLs.",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Enable deeper VST2 validation (exports + ctypes), slower but stricter.",
    )
    parser.add_argument(
        "--cache-db",
        default="vst-library-cache.sqlite",
        help="SQLite cache filename stored in output dir for fast incremental library builds.",
    )
    parser.add_argument(
        "--library-csv",
        default=None,
        help="Library CSV filename (default: VST-Library-YYYY.MM.DD.csv in output dir).",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    vst2_paths = args.vst2_path if args.vst2_path else DEFAULT_VST2_PATHS

    def _progress(message: str) -> None:
        if args.verbose:
            print(f"[progress] {message}")

    result = scan_plugins(
        vst2_paths=vst2_paths,
        vst3_path=args.vst3_path,
        progress_callback=_progress,
        progress_every=max(1, args.progress_every),
        max_files=args.max_files,
        scan_mode="deep" if args.deep else "shallow",
    )
    duplicates_file, uniques_file, json_file, remove_script_file = save_reports(
        result, output_dir=args.output_dir
    )
    library_summary = build_library_index(
        vst2_paths=vst2_paths,
        vst3_path=args.vst3_path,
        output_dir=args.output_dir,
        cache_db_name=args.cache_db,
        csv_name=args.library_csv,
        scan_mode="deep" if args.deep else "shallow",
        progress_callback=_progress,
        progress_every=max(1, args.progress_every),
    )

    print("\n=== Scan Summary ===")
    print(f"Scan mode: {result.scan_mode}")
    print("Dedupe key: vendor::plugin")
    print(f"Scanned VST2 DLL files: {result.scanned_vst2_files}")
    print(f"Scanned VST3 items: {result.scanned_vst3_items}")
    print(f"Detected real VST2 plugins: {result.vst2_detected}")
    print(f"VST2 with VST3 duplicates: {len(result.duplicates)}")
    print(f"VST2 without VST3 matches: {len(result.uniques)}")
    print(f"Skipped non-VST2 DLLs: {result.skipped_non_vst2}")
    print(f"Avg inspect time per VST2 DLL: {result.avg_inspection_ms:.2f} ms")
    print(f"Slowest single DLL inspect: {result.max_inspection_ms:.2f} ms")
    print(f"Avg VST3 identity extraction: {result.avg_vst3_identity_ms:.2f} ms")

    print("\n=== Output Files ===")
    print(duplicates_file)
    print(uniques_file)
    print(json_file)
    print(remove_script_file)
    print(library_summary.csv_file)
    print(library_summary.cache_db_file)

    print("\n=== Library Cache ===")
    print(f"Library rows written: {library_summary.rows_written}")
    print(f"VST2 rows: {library_summary.vst2_total}")
    print(f"VST3 rows: {library_summary.vst3_total}")
    print(f"Cache hits: {library_summary.cache_hits}")
    print(f"Cache misses: {library_summary.cache_misses}")


if __name__ == "__main__":
    main()
