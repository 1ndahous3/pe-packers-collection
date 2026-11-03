"""Validate locally built fixtures and record their provenance; does not run PEs."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
MACHINES = {"x86": (0x14C, 0x10B), "amd64": (0x8664, 0x20B)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_pe(path):
    data = path.read_bytes()
    def u16(offset):
        return struct.unpack_from("<H", data, offset)[0]
    def u32(offset):
        return struct.unpack_from("<I", data, offset)[0]
    def u64(offset):
        return struct.unpack_from("<Q", data, offset)[0]
    require(data[:2] == b"MZ", f"{path}: missing MZ header")
    pe = u32(0x3C)
    require(data[pe:pe + 4] == b"PE\0\0", f"{path}: missing PE signature")
    opt = pe + 24
    magic = u16(opt)
    require(magic in (0x10B, 0x20B), f"{path}: unsupported optional header")
    wide = magic == 0x20B
    directory = opt + (112 if wide else 96)
    section_table = opt + u16(pe + 20)
    sections = []
    for n in range(u16(pe + 6)):
        pos = section_table + 40 * n
        sections.append({
            "name": data[pos:pos + 8].rstrip(b"\0").decode("ascii"),
            "rva": u32(pos + 12), "virtual_size": u32(pos + 8),
            "raw_size": u32(pos + 16), "raw_offset": u32(pos + 20),
            "characteristics": f"0x{u32(pos + 36):08x}",
        })
    def offset(rva):
        if rva < u32(opt + 60):
            return rva
        for section in sections:
            delta = rva - section["rva"]
            if 0 <= delta < section["raw_size"]:
                return section["raw_offset"] + delta
        raise ValueError(f"{path}: RVA {rva:#x} has no file data")
    def string(rva):
        pos = offset(rva)
        return data[pos:data.index(b"\0", pos)].decode("ascii")
    imports = []
    import_rva = u32(directory + 8)
    if import_rva:
        pos = offset(import_rva)
        while any(data[pos:pos + 20]):
            imports.append(string(u32(pos + 12)))
            pos += 20
    exports = []
    export_rva = u32(directory)
    if export_rva:
        pos = offset(export_rva)
        count = u32(pos + 24)
        names, ordinals = offset(u32(pos + 32)), offset(u32(pos + 36))
        for n in range(count):
            exports.append({"name": string(u32(names + n * 4)),
                            "ordinal": u32(pos + 16) + u16(ordinals + n * 2)})
    return {
        "machine": f"0x{u16(pe + 4):04x}",
        "optional_header": f"0x{magic:04x}",
        "kind": "DLL" if u16(pe + 22) & 0x2000 else "EXE",
        "entry_point_rva": f"0x{u32(opt + 16):x}",
        "image_base": f"0x{(u64(opt + 24) if wide else u32(opt + 28)):x}",
        "dynamic_base": bool(u16(opt + 70) & 0x40),
        "nx_compatible": bool(u16(opt + 70) & 0x100),
        "relocations_size": u32(directory + 5 * 8 + 4),
        "tls_size": u32(directory + 9 * 8 + 4),
        "clr_size": u32(directory + 14 * 8 + 4),
        "imports": imports, "exports": exports, "sections": sections,
    }


def inspect_secrets(path, sections):
    data = path.read_bytes()
    spec = json.loads((ROOT / "src" / "secrets.json").read_text(encoding="utf-8"))
    records = []
    for marker in spec["markers"]:
        value = bytes.fromhex(marker["hex"])
        require(value, f"{marker['id']}: empty marker")
        checksum = 2166136261
        for byte in value:
            checksum = ((checksum ^ byte) * 16777619) & 0xffffffff
        require(f"{checksum:08x}" == marker["fnv1a32"],
                f"{marker['id']}: inconsistent reference checksum")
        start = data.find(value)
        require(start >= 0 and data.find(value, start + 1) == -1,
                f"{path.name}: expected exactly one copy of {marker['id']}")
        section = next((s for s in sections if
                        s["raw_offset"] <= start and
                        start + len(value) <= s["raw_offset"] + s["raw_size"]), None)
        require(section is not None and section["name"] == marker["section"],
                f"{path.name}: {marker['id']} is in the wrong section")
        permissions = int(section["characteristics"], 16) & 0xe0000000
        expected = {".text": 0x60000000, ".data": 0xc0000000,
                    ".rdata": 0x40000000, ".secret": 0x40000000}
        require(permissions == expected[marker["section"]],
                f"{path.name}: unexpected permissions for {marker['section']}")
        records.append({
            **marker, "size_bytes": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
            "file_offset": start,
            "rva": section["rva"] + start - section["raw_offset"],
        })
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--architecture", choices=MACHINES, required=True)
    parser.add_argument("--test-report", type=Path, required=True)
    args = parser.parse_args()
    arch = args.architecture
    build = ROOT / "build" / arch
    output = ROOT / "bin" / arch
    require(args.test_report.resolve() == (build / "verification.xml").resolve(),
            "Use the CTest report from this architecture's build directory")
    tests = list(ET.parse(args.test_report).getroot().iter("testcase"))
    require(len(tests) == 2 and {t.get("name") for t in tests} ==
            {"basic_exe_output", "basic_dll_rundll32"}, "Expected both baseline tests")
    require(all(t.get("status") == "run" and not any(
            t.find(tag) is not None for tag in ("failure", "error", "skipped"))
            for t in tests), "CTest report contains a failed or skipped test")
    build_info = json.loads((output / "build-info.json").read_text(encoding="utf-8"))
    require(build_info["architecture"] == arch, "Mismatched build metadata")
    require(sha256(output / "build-info.json") == sha256(build / "build-info.json"),
            "Installed metadata differs from the configured build")
    machine, magic = MACHINES[arch]
    artifacts = []
    for filename in ("basic.exe", "basic.dll"):
        path = output / filename
        tested = build / "bin" / "Release" / filename
        require(sha256(path) == sha256(tested), f"{filename}: differs from tested build")
        require(tested.stat().st_mtime_ns <= args.test_report.stat().st_mtime_ns,
                f"{filename}: newer than the test report; rerun CTest")
        pe = inspect_pe(path)
        require(int(pe["machine"], 16) == machine and
                int(pe["optional_header"], 16) == magic, f"{filename}: wrong architecture")
        require(pe["kind"] == ("DLL" if filename.endswith(".dll") else "EXE"),
                f"{filename}: wrong image kind")
        require(pe["dynamic_base"] and pe["nx_compatible"] and pe["relocations_size"] > 0,
                f"{filename}: missing ASLR/NX/relocations")
        require(not pe["tls_size"] and not pe["clr_size"], f"{filename}: unexpected TLS/CLR")
        require([name.upper() for name in pe["imports"]] == ["KERNEL32.DLL"],
                f"{filename}: unexpected runtime dependency")
        expected_exports = ([{"name": "FixtureAdd", "ordinal": 1},
                             {"name": "FixtureMessage", "ordinal": 2},
                             {"name": "RunFixture", "ordinal": 3}]
                            if pe["kind"] == "DLL" else [])
        require(pe["exports"] == expected_exports, f"{filename}: unexpected exports")
        artifacts.append({
            "id": f"basic-{pe['kind'].lower()}-{arch}",
            "role": "fixture", "path": filename, "sha256": sha256(path),
            "size_bytes": path.stat().st_size, "pe": pe,
            "secrets": inspect_secrets(path, pe["sections"]),
        })
    source_paths = [ROOT / "CMakeLists.txt", ROOT / "CMakePresets.json"]
    for folder in ("src", "cmake", "scripts"):
        source_paths.extend(p for p in (ROOT / folder).iterdir() if p.is_file())
    require(all(p.stat().st_mtime_ns <= args.test_report.stat().st_mtime_ns
                for p in source_paths), "Sources changed after CTest; rebuild and retest")
    manifest = {
        "format_version": 1, "family": "basic", "architecture": arch,
        "sample_kind": "benign", "build": build_info,
        "sources": [{"path": p.relative_to(ROOT).as_posix(), "sha256": sha256(p)}
                    for p in sorted(source_paths)],
        "artifacts": artifacts,
        "support_files": [{"path": name, "sha256": sha256(output / name)}
                          for name in ("build-info.json", "link/basic.lib")],
        "verification": {"static": "pass", "original_execution": "pass",
                         "command": f"ctest --preset {arch}",
                         "host": {"system": platform.system(), "version": platform.version(),
                                  "machine": platform.machine()},
                         "ctest_report_sha256": sha256(args.test_report),
                         "tests": sorted(t.get("name") for t in tests)},
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"{arch}: PE layout, secrets, installed hashes and both runtime tests verified")


if __name__ == "__main__":
    main()
