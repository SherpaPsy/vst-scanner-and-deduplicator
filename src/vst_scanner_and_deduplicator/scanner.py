from __future__ import annotations

import ctypes
import csv
import json
import re
import sqlite3
from difflib import SequenceMatcher
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Callable, Iterable, Literal

import pefile

DEFAULT_VST2_PATHS = [
    r"C:\Program Files\VSTPlugins",
    r"C:\Program Files (x86)\VSTPlugins",
    r"C:\Program Files\Common Files\VST2",
    r"C:\Program Files (x86)\Common Files\VST2",
    r"C:\Program Files\Steinberg\VSTPlugins",
    r"C:\Program Files (x86)\Steinberg\VSTPlugins",
]

DEFAULT_VST3_PATH = r"C:\Program Files\Common Files\VST3"

ScanMode = Literal["shallow", "deep"]

GENERIC_VENDOR_TOKENS = {
    "vst2",
    "vst3",
    "vstplugins",
    "common files",
    "program files",
    "program files (x86)",
    "contents",
    "x86_64-win",
    "x64",
    "win64",
    "win32",
    "plugins",
    "steinberg",
    "category",
    "file",
    "filetime",
    "metadatasource",
    "model",
    "product",
    "uniqueid",
    "version",
    "win32_baseboard",
}


@dataclass(slots=True)
class VST2Inspection:
    is_vst2: bool
    identity_plugin: str
    identity_vendor: str
    identity_key: str
    product_name: str | None
    company_name: str | None
    file_description: str | None
    exports: list[str]
    detected_by_ctypes: bool
    exports_ms: float
    ctypes_ms: float
    version_ms: float
    total_ms: float
    error: str | None = None


@dataclass(slots=True)
class VST3Identity:
    path: str
    plugin: str
    vendor: str
    match_key: str
    product_name: str | None
    company_name: str | None
    file_description: str | None
    identity_ms: float
    error: str | None = None


@dataclass(slots=True)
class VST2Plugin:
    path: str
    plugin: str
    vendor: str
    match_key: str
    has_vst3: bool
    matching_vst3_paths: list[str]
    inspection: VST2Inspection


@dataclass(slots=True)
class ScanResult:
    scan_mode: ScanMode
    scanned_vst2_files: int
    scanned_vst3_items: int
    vst2_detected: int
    duplicates: list[VST2Plugin]
    uniques: list[VST2Plugin]
    skipped_non_vst2: int
    avg_inspection_ms: float
    max_inspection_ms: float
    avg_vst3_identity_ms: float


@dataclass(slots=True)
class LibraryBuildSummary:
    vst2_total: int
    vst3_total: int
    rows_written: int
    cache_hits: int
    cache_misses: int
    csv_file: Path
    cache_db_file: Path


ProgressCallback = Callable[[str], None]


def _normalize_identity_component(value: str | None, fallback: str) -> str:
    candidate = (value or "").strip()
    if not candidate:
        candidate = fallback.strip()
    normalized = " ".join(candidate.lower().split())
    return normalized or "unknown"


def _normalize_plugin_name_for_matching(plugin_name: str) -> str:
    normalized = _normalize_identity_component(plugin_name, plugin_name)
    normalized = normalized.replace("-vst3", "-vst")
    normalized = normalized.replace(" vst3", " vst")
    normalized = normalized.replace("vst3 ", "vst ")
    return " ".join(normalized.split())


def _plugin_core_name(plugin_name: str, vendor: str) -> str:
    core = re.sub(r"[^a-z0-9]+", "", plugin_name.lower())

    if vendor == "izotope":
        if core.startswith("izotope"):
            core = core[len("izotope") :]
        if core.startswith("iz") and len(core) > 4:
            core = core[2:]
        core = core.replace("dialoguedenoiser", "dialoguedenoise")
        core = core.replace("declicker", "declick")
        core = core.replace("declipper", "declip")
        core = core.replace("humremoval", "dehum")
    return core


def _plugins_match(v2_plugin: str, v2_vendor: str, v3_plugin: str, v3_vendor: str) -> bool:
    if v2_vendor != v3_vendor:
        return False

    v2_core = _plugin_core_name(v2_plugin, v2_vendor)
    v3_core = _plugin_core_name(v3_plugin, v3_vendor)
    if not v2_core or not v3_core:
        return False

    if v2_core == v3_core:
        return True

    shorter, longer = (v2_core, v3_core) if len(v2_core) <= len(v3_core) else (v3_core, v2_core)
    if len(shorter) >= 4 and longer.startswith(shorter):
        return True

    similarity = SequenceMatcher(None, v2_core, v3_core).ratio()
    return similarity >= 0.9


def _is_generic_vendor(value: str | None) -> bool:
    normalized = _normalize_identity_component(value, "unknown")
    if normalized in GENERIC_VENDOR_TOKENS:
        return True
    return normalized.startswith("vst") and normalized.endswith("plugins")


def _is_suspicious_plugin_value(value: str | None) -> bool:
    normalized = _normalize_identity_component(value, "")
    if not normalized or normalized == "unknown":
        return True

    known_bad_tokens = {
        "cast5-cbc",
        "device_id",
        "fileversion",
        "translation",
        "comment",
        "tags",
        "category",
        "publisher",
        "manufacturer",
    }
    if normalized in known_bad_tokens:
        return True

    if any(token in normalized for token in ("\\", "/", "<", ">", "|", "::")):
        return True

    return False


def _infer_vendor_from_stem(stem: str) -> str | None:
    lowered = stem.lower()
    if lowered.startswith("bx_") or lowered.startswith("bx "):
        return "brainworx"

    izotope_prefixes = (
        "iz",
        "izotope",
        "rx ",
        "ozone",
        "neutron",
        "nectar",
        "neoverb",
        "iris",
        "insight",
        "relay",
        "vinyl",
        "vocal doubler",
        "vocalsynth",
        "stutter",
        "tonal balance",
    )
    if lowered.startswith(izotope_prefixes):
        return "izotope"

    if lowered.startswith("tdr ") or lowered.startswith("tdr_"):
        return "tokyo dawn labs"

    if lowered.startswith("valhalla"):
        return "valhalla dsp"

    if lowered.startswith("waveshell") or lowered.startswith("waves "):
        return "waves"

    if lowered.startswith("kick "):
        return "sonic academy"

    if lowered.startswith("halftime"):
        return "cableguys"

    return None


def _infer_vendor_from_plugin_name(plugin_name: str) -> str | None:
    lowered = plugin_name.lower()

    if lowered.startswith("bx_") or lowered.startswith("bx "):
        return "brainworx"
    if lowered.startswith("tdr ") or lowered.startswith("tdr_"):
        return "tokyo dawn labs"
    if lowered.startswith("valhalla"):
        return "valhalla dsp"
    if lowered.startswith("waveshell") or lowered.startswith("waves "):
        return "waves"
    if lowered.startswith("kick "):
        return "sonic academy"
    if lowered.startswith("halftime"):
        return "cableguys"

    izotope_prefixes = (
        "iz",
        "izotope",
        "rx ",
        "ozone",
        "neutron",
        "nectar",
        "neoverb",
        "iris",
        "insight",
        "relay",
        "vinyl",
        "vocal doubler",
        "vocalsynth",
        "stutter",
        "tonal balance",
    )
    if lowered.startswith(izotope_prefixes):
        return "izotope"

    return None


def _infer_vendor_from_path(file_path: Path) -> str:
    for parent in file_path.parents:
        if not parent.name:
            continue
        candidate = _normalize_identity_component(parent.name, "unknown")
        if candidate == "unknown" or _is_generic_vendor(candidate):
            continue
        if candidate.endswith(".vst") or candidate.endswith(".vst3"):
            continue
        return candidate
    return "unknown"


def _derive_identity(
    path: Path,
    product_name: str | None,
    company_name: str | None,
    file_description: str | None,
    scan_mode: ScanMode,
) -> tuple[str, str, str]:
    filename_plugin = _normalize_identity_component(path.stem, path.stem)

    if scan_mode == "shallow":
        plugin = filename_plugin
    else:
        metadata_plugin = _normalize_identity_component(product_name or file_description, path.stem)
        plugin = filename_plugin if _is_suspicious_plugin_value(metadata_plugin) else metadata_plugin

    plugin = _normalize_plugin_name_for_matching(plugin)

    inferred_vendor = _infer_vendor_from_stem(path.stem) or _infer_vendor_from_path(path)
    if scan_mode == "deep" and company_name and not _is_generic_vendor(company_name):
        vendor = _normalize_identity_component(company_name, inferred_vendor)
    else:
        vendor = inferred_vendor

    vendor_from_plugin = _infer_vendor_from_plugin_name(plugin)
    if vendor == "unknown" or _is_generic_vendor(vendor):
        vendor = vendor_from_plugin or "unknown"

    return plugin, vendor, f"{vendor}::{plugin}"


def extract_strings_streaming(
    path: str,
    min_length: int = 4,
    chunk_size: int = 65536,
) -> Iterable[str]:
    pattern = re.compile(rb"[ -~]{" + str(min_length).encode("ascii") + rb",}")
    buffer = b""

    with open(path, "rb") as file_obj:
        while chunk := file_obj.read(chunk_size):
            buffer += chunk
            parts = pattern.findall(buffer)
            if not parts:
                buffer = buffer[-chunk_size:]
                continue

            for part in parts[:-1]:
                yield part.decode("ascii", errors="ignore")

            buffer = parts[-1]

    if buffer and pattern.fullmatch(buffer):
        yield buffer.decode("ascii", errors="ignore")


def _extract_version_strings_streaming(
    path: str,
    max_strings: int = 50000,
) -> tuple[str | None, str | None, str | None]:
    aliases = {
        "product_name": {"productname", "product name"},
        "company_name": {"companyname", "company name", "vendor", "manufacturer"},
        "file_description": {"filedescription", "file description", "description"},
    }

    product_name = None
    company_name = None
    file_description = None
    pending_key: str | None = None

    for idx, raw_value in enumerate(extract_strings_streaming(path), start=1):
        value = " ".join(raw_value.replace("\x00", " ").split()).strip(" :=-\t\n\r")
        if not value:
            continue

        lowered = value.lower()

        if pending_key:
            if pending_key == "product_name" and product_name is None:
                product_name = value
            elif pending_key == "company_name" and company_name is None:
                company_name = value
            elif pending_key == "file_description" and file_description is None:
                file_description = value
            pending_key = None

            if product_name and company_name and file_description:
                break
            if idx >= max_strings:
                break
            continue

        if lowered in aliases["product_name"]:
            pending_key = "product_name"
        elif lowered in aliases["company_name"]:
            pending_key = "company_name"
        elif lowered in aliases["file_description"]:
            pending_key = "file_description"

        if idx >= max_strings:
            break

    return product_name, company_name, file_description


def _extract_string_fields_streaming(
    path: str,
    max_strings: int = 70000,
) -> dict[str, str | None]:
    aliases = {
        "product_name": {"productname", "product name"},
        "company_name": {"companyname", "company name", "vendor", "manufacturer"},
        "file_description": {"filedescription", "file description", "description"},
        "file_version": {"fileversion", "file version"},
        "product_version": {"productversion", "product version"},
        "type_category": {"category", "plugincategory", "plugin category", "type"},
        "subtype": {"subtype", "sub type", "subcategory", "sub category", "sub-category"},
    }
    values: dict[str, str | None] = {key: None for key in aliases}
    pending_key: str | None = None

    for idx, raw_value in enumerate(extract_strings_streaming(path), start=1):
        value = " ".join(raw_value.replace("\x00", " ").split()).strip(" :=-\t\n\r")
        if not value:
            continue
        lowered = value.lower()

        if pending_key:
            if values[pending_key] is None:
                values[pending_key] = value
            pending_key = None
            if idx >= max_strings:
                break
            continue

        for key, tokens in aliases.items():
            if lowered in tokens and values[key] is None:
                pending_key = key
                break

        if idx >= max_strings:
            break

    return values


def _detect_architecture(path_obj: Path) -> str:
    lowered = str(path_obj).lower()
    if "x86_64" in lowered or "_x64" in lowered or "64" in lowered:
        guessed = "64-bit"
    elif "x86" in lowered or "32" in lowered:
        guessed = "32-bit"
    else:
        guessed = "unknown"

    if path_obj.is_dir():
        return guessed

    try:
        pe = pefile.PE(str(path_obj), fast_load=True)
        machine = pe.FILE_HEADER.Machine
        pe.close()
        if machine == 0x8664:
            return "64-bit"
        if machine == 0x14C:
            return "32-bit"
        if machine == 0xAA64:
            return "arm64"
    except Exception:
        pass

    return guessed


def _library_extra_fields(path_obj: Path) -> dict[str, str]:
    if path_obj.is_dir():
        return {
            "version": "",
            "type_category": "",
            "subtype": "",
            "architecture": _detect_architecture(path_obj),
        }

    fields = _extract_string_fields_streaming(str(path_obj))
    version = fields.get("product_version") or fields.get("file_version") or ""
    type_category = fields.get("type_category") or ""
    subtype = fields.get("subtype") or ""
    architecture = _detect_architecture(path_obj)
    return {
        "version": version,
        "type_category": type_category,
        "subtype": subtype,
        "architecture": architecture,
    }


def _collect_files_with_progress(
    paths: Iterable[str],
    suffix: str,
    label: str,
    progress_callback: ProgressCallback | None = None,
    progress_every: int = 200,
    include_directories: bool = False,
) -> list[Path]:
    files: list[Path] = []
    for raw_path in paths:
        root = Path(raw_path)
        if not root.exists():
            if progress_callback:
                progress_callback(f"Skipping missing {label} path: {root}")
            continue

        if progress_callback:
            progress_callback(f"Scanning {label} path: {root}")

        for item in root.rglob(f"*{suffix}"):
            if not include_directories and not item.is_file():
                continue
            if include_directories and not (item.is_file() or item.is_dir()):
                continue
            files.append(item)
            if progress_callback and len(files) % progress_every == 0:
                progress_callback(f"Found {len(files)} {label} candidates so far...")

    if progress_callback:
        progress_callback(f"Discovery complete: {len(files)} {label} candidates.")
    return files


def _extract_exports(path: str) -> list[str]:
    exports: list[str] = []
    pe = pefile.PE(path, fast_load=False)
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if entry.name:
                    exports.append(entry.name.decode("ascii", errors="ignore"))
        else:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
            )
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if entry.name:
                        exports.append(entry.name.decode("ascii", errors="ignore"))
    finally:
        pe.close()
    return exports


def _extract_version_strings(path: str) -> tuple[str | None, str | None, str | None]:
    pe = pefile.PE(path)
    product_name = None
    company_name = None
    file_description = None

    try:
        if hasattr(pe, "FileInfo"):
            for file_info in pe.FileInfo:
                if file_info.Key != b"StringFileInfo":
                    continue
                for string_table in file_info.StringTable:
                    entries = {
                        key.decode("utf-8", errors="ignore"): value.decode(
                            "utf-8", errors="ignore"
                        )
                        for key, value in string_table.entries.items()
                    }
                    product_name = entries.get("ProductName") or product_name
                    company_name = entries.get("CompanyName") or company_name
                    file_description = entries.get("FileDescription") or file_description
    finally:
        pe.close()

    return product_name, company_name, file_description


def _detect_vst2_with_ctypes(path: str) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    load_library_ex_w = kernel32.LoadLibraryExW
    load_library_ex_w.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
    load_library_ex_w.restype = ctypes.c_void_p

    get_proc_address = kernel32.GetProcAddress
    get_proc_address.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    get_proc_address.restype = ctypes.c_void_p

    free_library = kernel32.FreeLibrary
    free_library.argtypes = [ctypes.c_void_p]
    free_library.restype = ctypes.c_int

    DONT_RESOLVE_DLL_REFERENCES = 0x00000001
    module_handle = load_library_ex_w(path, None, DONT_RESOLVE_DLL_REFERENCES)
    if not module_handle:
        return False

    try:
        vst_plugin_main = get_proc_address(module_handle, b"VSTPluginMain")
        legacy_main = get_proc_address(module_handle, b"main")
        return bool(vst_plugin_main or legacy_main)
    finally:
        free_library(module_handle)


def inspect_vst2(path: str, scan_mode: ScanMode) -> VST2Inspection:
    inspect_start = perf_counter()
    exports_ms = 0.0
    ctypes_ms = 0.0
    version_ms = 0.0

    file_path = Path(path)

    try:
        version_start = perf_counter()
        if scan_mode == "deep":
            product_name, company_name, file_description = _extract_version_strings(path)
        else:
            product_name, company_name, file_description = _extract_version_strings_streaming(path)
        version_ms = (perf_counter() - version_start) * 1000

        plugin, vendor, identity_key = _derive_identity(
            file_path,
            product_name=product_name,
            company_name=company_name,
            file_description=file_description,
            scan_mode=scan_mode,
        )

        exports: list[str] = []
        ctypes_based_match = False
        is_vst2 = True

        if scan_mode == "deep":
            export_start = perf_counter()
            exports = _extract_exports(path)
            exports_ms = (perf_counter() - export_start) * 1000

            export_based_match = any(name in {"VSTPluginMain", "main"} for name in exports)

            ctypes_start = perf_counter()
            ctypes_based_match = _detect_vst2_with_ctypes(path)
            ctypes_ms = (perf_counter() - ctypes_start) * 1000
            is_vst2 = bool(export_based_match or ctypes_based_match)

        total_ms = (perf_counter() - inspect_start) * 1000

        return VST2Inspection(
            is_vst2=is_vst2,
            identity_plugin=plugin,
            identity_vendor=vendor,
            identity_key=identity_key,
            product_name=product_name,
            company_name=company_name,
            file_description=file_description,
            exports=exports,
            detected_by_ctypes=ctypes_based_match,
            exports_ms=round(exports_ms, 3),
            ctypes_ms=round(ctypes_ms, 3),
            version_ms=round(version_ms, 3),
            total_ms=round(total_ms, 3),
        )
    except Exception as exc:
        plugin, vendor, identity_key = _derive_identity(
            file_path,
            product_name=None,
            company_name=None,
            file_description=None,
            scan_mode=scan_mode,
        )
        total_ms = (perf_counter() - inspect_start) * 1000
        return VST2Inspection(
            is_vst2=False if scan_mode == "deep" else True,
            identity_plugin=plugin,
            identity_vendor=vendor,
            identity_key=identity_key,
            product_name=None,
            company_name=None,
            file_description=None,
            exports=[],
            detected_by_ctypes=False,
            exports_ms=round(exports_ms, 3),
            ctypes_ms=round(ctypes_ms, 3),
            version_ms=round(version_ms, 3),
            total_ms=round(total_ms, 3),
            error=str(exc),
        )


def inspect_vst3_identity(path: str) -> VST3Identity:
    start = perf_counter()
    file_path = Path(path)

    try:
        if file_path.is_dir():
            plugin, vendor, match_key = _derive_identity(
                file_path,
                product_name=None,
                company_name=None,
                file_description=None,
                scan_mode="shallow",
            )
            return VST3Identity(
                path=path,
                plugin=plugin,
                vendor=vendor,
                match_key=match_key,
                product_name=None,
                company_name=None,
                file_description=None,
                identity_ms=round((perf_counter() - start) * 1000, 3),
            )

        product_name, company_name, file_description = _extract_version_strings_streaming(path)
        plugin, vendor, match_key = _derive_identity(
            file_path,
            product_name=product_name,
            company_name=company_name,
            file_description=file_description,
            scan_mode="shallow",
        )

        return VST3Identity(
            path=path,
            plugin=plugin,
            vendor=vendor,
            match_key=match_key,
            product_name=product_name,
            company_name=company_name,
            file_description=file_description,
            identity_ms=round((perf_counter() - start) * 1000, 3),
        )
    except Exception as exc:
        plugin, vendor, match_key = _derive_identity(
            file_path,
            product_name=None,
            company_name=None,
            file_description=None,
            scan_mode="shallow",
        )
        return VST3Identity(
            path=path,
            plugin=plugin,
            vendor=vendor,
            match_key=match_key,
            product_name=None,
            company_name=None,
            file_description=None,
            identity_ms=round((perf_counter() - start) * 1000, 3),
            error=str(exc),
        )


def scan_plugins(
    vst2_paths: list[str],
    vst3_path: str,
    progress_callback: ProgressCallback | None = None,
    progress_every: int = 50,
    max_files: int | None = None,
    scan_mode: ScanMode = "shallow",
) -> ScanResult:
    vst2_candidates = _collect_files_with_progress(
        paths=vst2_paths,
        suffix=".dll",
        label="VST2",
        progress_callback=progress_callback,
        progress_every=max(1, progress_every),
    )
    if max_files is not None:
        vst2_candidates = vst2_candidates[: max(0, max_files)]
        if progress_callback:
            progress_callback(
                f"Debug cap active: processing first {len(vst2_candidates)} VST2 files."
            )

    vst3_bundle_candidates = _collect_files_with_progress(
        paths=[vst3_path],
        suffix=".vst3",
        label="VST3 bundles",
        progress_callback=progress_callback,
        progress_every=max(1, progress_every),
        include_directories=True,
    )

    vst3_dll_candidates = _collect_files_with_progress(
        paths=[vst3_path],
        suffix=".dll",
        label="VST3 dlls",
        progress_callback=progress_callback,
        progress_every=max(1, progress_every),
    )

    merged_vst3_paths: dict[str, Path] = {}
    for candidate in [*vst3_bundle_candidates, *vst3_dll_candidates]:
        merged_vst3_paths[str(candidate).lower()] = candidate
    vst3_candidates = list(merged_vst3_paths.values())

    vst3_by_key: dict[str, list[str]] = {}
    vst3_identity_rows: list[VST3Identity] = []
    vst3_ms_total = 0.0
    for index, vst3_file in enumerate(vst3_candidates, start=1):
        if progress_callback and (index == 1 or index % max(1, progress_every) == 0):
            progress_callback(f"Profiling VST3 identity {index}/{len(vst3_candidates)}: {vst3_file}")

        vst3_identity = inspect_vst3_identity(str(vst3_file))
        vst3_ms_total += vst3_identity.identity_ms
        vst3_identity_rows.append(vst3_identity)
        vst3_by_key.setdefault(vst3_identity.match_key, []).append(vst3_identity.path)

    duplicates: list[VST2Plugin] = []
    uniques: list[VST2Plugin] = []
    skipped_non_vst2 = 0
    inspected_ms_total = 0.0
    inspected_max_ms = 0.0

    total = len(vst2_candidates)
    for index, dll in enumerate(vst2_candidates, start=1):
        if progress_callback and (index == 1 or index % max(1, progress_every) == 0):
            progress_callback(f"Inspecting VST2 DLL {index}/{total}: {dll}")

        inspection = inspect_vst2(str(dll), scan_mode=scan_mode)
        inspected_ms_total += inspection.total_ms
        inspected_max_ms = max(inspected_max_ms, inspection.total_ms)

        if not inspection.is_vst2:
            skipped_non_vst2 += 1
            continue

        matched_vst3_paths = vst3_by_key.get(inspection.identity_key, [])
        if not matched_vst3_paths:
            matched_vst3_paths = [
                row.path
                for row in vst3_identity_rows
                if _plugins_match(
                    v2_plugin=inspection.identity_plugin,
                    v2_vendor=inspection.identity_vendor,
                    v3_plugin=row.plugin,
                    v3_vendor=row.vendor,
                )
            ]
        record = VST2Plugin(
            path=str(dll),
            plugin=inspection.identity_plugin,
            vendor=inspection.identity_vendor,
            match_key=inspection.identity_key,
            has_vst3=bool(matched_vst3_paths),
            matching_vst3_paths=matched_vst3_paths,
            inspection=inspection,
        )

        if record.has_vst3:
            duplicates.append(record)
        else:
            uniques.append(record)

    inspected_count = len(vst2_candidates)
    avg_ms = (inspected_ms_total / inspected_count) if inspected_count else 0.0
    avg_vst3_identity_ms = (
        (vst3_ms_total / len(vst3_candidates)) if vst3_candidates else 0.0
    )

    if progress_callback:
        progress_callback(
            "Inspection complete: "
            f"{len(duplicates)} duplicates, {len(uniques)} unique, {skipped_non_vst2} non-VST2. "
            f"Avg VST2 inspect/file: {avg_ms:.2f} ms, max: {inspected_max_ms:.2f} ms. "
            f"Avg VST3 identity/file: {avg_vst3_identity_ms:.2f} ms."
        )

    return ScanResult(
        scan_mode=scan_mode,
        scanned_vst2_files=len(vst2_candidates),
        scanned_vst3_items=len(vst3_candidates),
        vst2_detected=len(duplicates) + len(uniques),
        duplicates=sorted(duplicates, key=lambda item: (item.vendor, item.plugin)),
        uniques=sorted(uniques, key=lambda item: (item.vendor, item.plugin)),
        skipped_non_vst2=skipped_non_vst2,
        avg_inspection_ms=round(avg_ms, 3),
        max_inspection_ms=round(inspected_max_ms, 3),
        avg_vst3_identity_ms=round(avg_vst3_identity_ms, 3),
    )


def _init_library_cache(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS plugin_cache (
            path TEXT NOT NULL,
            scan_kind TEXT NOT NULL,
            scan_mode TEXT NOT NULL,
            modified_ns INTEGER NOT NULL,
            size_bytes INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (path, scan_kind, scan_mode)
        )
        """
    )


def _load_from_cache(
    conn: sqlite3.Connection,
    path: str,
    scan_kind: str,
    scan_mode: str,
    modified_ns: int,
    size_bytes: int,
    required_keys: set[str] | None = None,
) -> dict | None:
    row = conn.execute(
        """
        SELECT payload_json, modified_ns, size_bytes
        FROM plugin_cache
        WHERE path = ? AND scan_kind = ? AND scan_mode = ?
        """,
        (path, scan_kind, scan_mode),
    ).fetchone()
    if not row:
        return None

    payload_json, cached_modified_ns, cached_size_bytes = row
    if cached_modified_ns != modified_ns or cached_size_bytes != size_bytes:
        return None
    payload = json.loads(payload_json)
    if required_keys and not required_keys.issubset(set(payload.keys())):
        return None
    return payload


def _save_to_cache(
    conn: sqlite3.Connection,
    path: str,
    scan_kind: str,
    scan_mode: str,
    modified_ns: int,
    size_bytes: int,
    payload: dict,
) -> None:
    conn.execute(
        """
        INSERT INTO plugin_cache (
            path, scan_kind, scan_mode, modified_ns, size_bytes, payload_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(path, scan_kind, scan_mode) DO UPDATE SET
            modified_ns = excluded.modified_ns,
            size_bytes = excluded.size_bytes,
            payload_json = excluded.payload_json,
            updated_at = excluded.updated_at
        """,
        (
            path,
            scan_kind,
            scan_mode,
            modified_ns,
            size_bytes,
            json.dumps(payload),
            datetime.now().isoformat(timespec="seconds"),
        ),
    )


def _safe_stat(path: Path) -> tuple[int, int, str]:
    stat = path.stat()
    modified_ns = int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000)))
    modified_utc = datetime.utcfromtimestamp(stat.st_mtime).isoformat(timespec="seconds") + "Z"
    return modified_ns, stat.st_size, modified_utc


def build_library_index(
    vst2_paths: list[str],
    vst3_path: str,
    output_dir: str,
    cache_db_name: str = "vst-library-cache.sqlite",
    csv_name: str | None = None,
    scan_mode: ScanMode = "shallow",
    progress_callback: ProgressCallback | None = None,
    progress_every: int = 50,
) -> LibraryBuildSummary:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now().strftime("%Y.%m.%d")
    csv_file = out_dir / (csv_name or f"VST-Library-{stamp}.csv")
    cache_db_file = out_dir / cache_db_name

    vst2_candidates = _collect_files_with_progress(
        paths=vst2_paths,
        suffix=".dll",
        label="VST2",
        progress_callback=progress_callback,
        progress_every=max(1, progress_every),
    )
    vst3_bundle_candidates = _collect_files_with_progress(
        paths=[vst3_path],
        suffix=".vst3",
        label="VST3 bundles",
        progress_callback=progress_callback,
        progress_every=max(1, progress_every),
        include_directories=True,
    )
    vst3_dll_candidates = _collect_files_with_progress(
        paths=[vst3_path],
        suffix=".dll",
        label="VST3 dlls",
        progress_callback=progress_callback,
        progress_every=max(1, progress_every),
    )

    merged_vst3_paths: dict[str, Path] = {}
    for candidate in [*vst3_bundle_candidates, *vst3_dll_candidates]:
        merged_vst3_paths[str(candidate).lower()] = candidate
    vst3_candidates = list(merged_vst3_paths.values())

    cache_hits = 0
    cache_misses = 0
    required_cache_keys = {
        "plugin",
        "vendor",
        "match_key",
        "version",
        "type_category",
        "subtype",
        "architecture",
    }

    vst3_rows: list[dict] = []
    vst3_by_key: dict[str, list[str]] = {}
    vst2_rows: list[dict] = []

    conn = sqlite3.connect(cache_db_file)
    try:
        _init_library_cache(conn)

        for idx, path_obj in enumerate(vst3_candidates, start=1):
            if progress_callback and (idx == 1 or idx % max(1, progress_every) == 0):
                progress_callback(f"Library VST3 {idx}/{len(vst3_candidates)}: {path_obj}")

            path_str = str(path_obj)
            modified_ns, size_bytes, modified_utc = _safe_stat(path_obj)
            cached = _load_from_cache(
                conn,
                path=path_str,
                scan_kind="vst3",
                scan_mode="shallow",
                modified_ns=modified_ns,
                size_bytes=size_bytes,
                required_keys=required_cache_keys,
            )

            if cached:
                cache_hits += 1
                row_payload = cached
                from_cache = True
            else:
                identity = inspect_vst3_identity(path_str)
                extra_fields = _library_extra_fields(path_obj)
                row_payload = {
                    "plugin": identity.plugin,
                    "vendor": identity.vendor,
                    "match_key": identity.match_key,
                    "error": identity.error,
                    "product_name": identity.product_name,
                    "company_name": identity.company_name,
                    "file_description": identity.file_description,
                    "version": extra_fields["version"],
                    "type_category": extra_fields["type_category"],
                    "subtype": extra_fields["subtype"],
                    "architecture": extra_fields["architecture"],
                }
                _save_to_cache(
                    conn,
                    path=path_str,
                    scan_kind="vst3",
                    scan_mode="shallow",
                    modified_ns=modified_ns,
                    size_bytes=size_bytes,
                    payload=row_payload,
                )
                cache_misses += 1
                from_cache = False

            row = {
                "name": row_payload["plugin"],
                "vendor": row_payload["vendor"],
                "version": row_payload.get("version") or "",
                "format": "vst3",
                "type/category": row_payload.get("type_category") or "",
                "subtype": row_payload.get("subtype") or "",
                "architecture": row_payload.get("architecture") or "unknown",
                "last modified date": modified_utc,
                "full-path": path_str,
                "_cache": from_cache,
                "_error": row_payload.get("error") or "",
            }
            vst3_rows.append(row)
            vst3_by_key.setdefault(row_payload["match_key"], []).append(path_str)

        for idx, path_obj in enumerate(vst2_candidates, start=1):
            if progress_callback and (idx == 1 or idx % max(1, progress_every) == 0):
                progress_callback(f"Library VST2 {idx}/{len(vst2_candidates)}: {path_obj}")

            path_str = str(path_obj)
            modified_ns, size_bytes, modified_utc = _safe_stat(path_obj)
            cached = _load_from_cache(
                conn,
                path=path_str,
                scan_kind="vst2",
                scan_mode=scan_mode,
                modified_ns=modified_ns,
                size_bytes=size_bytes,
                required_keys=required_cache_keys,
            )

            if cached:
                cache_hits += 1
                row_payload = cached
                from_cache = True
            else:
                inspected = inspect_vst2(path_str, scan_mode=scan_mode)
                extra_fields = _library_extra_fields(path_obj)
                row_payload = {
                    "plugin": inspected.identity_plugin,
                    "vendor": inspected.identity_vendor,
                    "match_key": inspected.identity_key,
                    "is_vst2": inspected.is_vst2,
                    "error": inspected.error,
                    "product_name": inspected.product_name,
                    "company_name": inspected.company_name,
                    "file_description": inspected.file_description,
                    "version": extra_fields["version"],
                    "type_category": extra_fields["type_category"],
                    "subtype": extra_fields["subtype"],
                    "architecture": extra_fields["architecture"],
                }
                _save_to_cache(
                    conn,
                    path=path_str,
                    scan_kind="vst2",
                    scan_mode=scan_mode,
                    modified_ns=modified_ns,
                    size_bytes=size_bytes,
                    payload=row_payload,
                )
                cache_misses += 1
                from_cache = False

            has_vst3_duplicate = bool(vst3_by_key.get(row_payload["match_key"], []))
            row = {
                "name": row_payload["plugin"],
                "vendor": row_payload["vendor"],
                "version": row_payload.get("version") or "",
                "format": "vst2",
                "type/category": row_payload.get("type_category") or "",
                "subtype": row_payload.get("subtype") or "",
                "architecture": row_payload.get("architecture") or "unknown",
                "last modified date": modified_utc,
                "full-path": path_str,
                "_cache": from_cache,
                "_error": row_payload.get("error") or "",
                "_has_vst3_duplicate": has_vst3_duplicate,
            }
            vst2_rows.append(row)

        conn.commit()
    finally:
        conn.close()

    all_rows = [*vst2_rows, *vst3_rows]
    all_rows.sort(key=lambda row: (row["format"], row["vendor"], row["name"], row["full-path"]))

    fieldnames = [
        "name",
        "vendor",
        "version",
        "format",
        "type/category",
        "subtype",
        "architecture",
        "last modified date",
        "full-path",
    ]

    try:
        with csv_file.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in all_rows:
                writer.writerow({key: row.get(key, "") for key in fieldnames})
    except PermissionError:
        fallback_csv = out_dir / f"VST-Library-{datetime.now().strftime('%Y.%m.%d-%H%M%S')}.csv"
        with fallback_csv.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in all_rows:
                writer.writerow({key: row.get(key, "") for key in fieldnames})
        csv_file = fallback_csv

    return LibraryBuildSummary(
        vst2_total=len(vst2_rows),
        vst3_total=len(vst3_rows),
        rows_written=len(all_rows),
        cache_hits=cache_hits,
        cache_misses=cache_misses,
        csv_file=csv_file,
        cache_db_file=cache_db_file,
    )


def save_reports(result: ScanResult, output_dir: str) -> tuple[Path, Path, Path, Path]:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y.%m.%d")

    duplicates_file = out_dir / f"VST2-Duplicates-{stamp}.txt"
    uniques_file = out_dir / f"VST2-Unique-{stamp}.txt"
    json_file = out_dir / f"VST-Scan-{stamp}.json"
    remove_script_file = out_dir / "remove-vst2-duplicates.ps1"

    duplicates_lines = [
        "=== VST2 plugins that HAVE VST3 versions (deduplicated by vendor + plugin) ===",
        *[
            f"{row.vendor} | {row.plugin} | {row.path}"
            for row in result.duplicates
        ],
    ]

    uniques_lines = [
        "=== VST2 plugins WITHOUT VST3 versions (deduplicated by vendor + plugin) ===",
        *[
            f"{row.vendor} | {row.plugin} | {row.path}"
            for row in result.uniques
        ],
    ]

    duplicates_file.write_text("\n".join(duplicates_lines), encoding="utf-8")
    uniques_file.write_text("\n".join(uniques_lines), encoding="utf-8")

    payload = {
        "summary": {
            "scan_mode": result.scan_mode,
            "dedupe_key": "vendor::plugin",
            "scanned_vst2_files": result.scanned_vst2_files,
            "scanned_vst3_items": result.scanned_vst3_items,
            "vst2_detected": result.vst2_detected,
            "duplicates": len(result.duplicates),
            "uniques": len(result.uniques),
            "skipped_non_vst2": result.skipped_non_vst2,
            "avg_inspection_ms": result.avg_inspection_ms,
            "max_inspection_ms": result.max_inspection_ms,
            "avg_vst3_identity_ms": result.avg_vst3_identity_ms,
        },
        "duplicates": [asdict(row) for row in result.duplicates],
        "uniques": [asdict(row) for row in result.uniques],
    }
    json_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    remove_lines = [
        "# Auto-generated by vst-scan",
        "# Review before running. This permanently removes listed VST2 files.",
        "# Auto-elevate if not running as admin",
        "if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()",
        "    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {",
        "",
        "    Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoExit', '-ExecutionPolicy', 'Bypass', '-File', \"`\"$PSCommandPath`\"\")",
        "    exit",
        "}",
        "",
    ]
    for row in result.duplicates:
        escaped_path = row.path.replace('"', '""')
        remove_lines.append(f'Remove-Item -LiteralPath "{escaped_path}" -Force')
    remove_script_file.write_text("\n".join(remove_lines) + "\n", encoding="utf-8")

    return duplicates_file, uniques_file, json_file, remove_script_file
