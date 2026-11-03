"""Compare fixture PE headers, sections, imports, exports and relocations.

Usage (from the collection root)
--------------------------------
  python tools/compare_pe.py ORIGINAL RESTORED
  python tools/compare_pe.py fixtures/bin/x86/basic.exe path/to/restored.exe

Python 3.8+; standard library only. Paths are relative to the current working
directory. The command reads two files and prints JSON to stdout; it does
not execute binaries, modify inputs or write reports.

The module interface compare(original_bytes, restored_bytes) returns the
same dictionary. Packer generators can use it alongside their own execution
and secret checks.

Compared data
--------------
PE32/PE32+ DOS header, DOS stub/Rich region, PE/COFF/fixed optional header,
data directories, full section headers and header padding; decoded header
fields; raw section bytes; import names/hints; export names/ordinals/RVAs;
non-padding relocation types/targets and block layout.

Byte difference counts use corresponding file positions and include length
differences. Sections are paired in table order. Relocation comparison skips
type-0 padding, but retains block details and reports incomplete or invalid
tails explicitly. Matching active relocation entries alone does not prove
that the entire relocation directory is well formed.

This is a diagnostic helper for the collection's fixtures, not a complete
PE validator. Successful comparison exits 0 even when files differ or a
relocation issue is reported; callers must inspect the result. File/parse
errors exit nonzero. Runtime and secret checks are separate operations.
"""
import struct

DIRECTORY_NAMES = (
    "export", "import", "resource", "exception", "security", "base_relocation",
    "debug", "architecture", "global_pointer", "tls", "load_config",
    "bound_import", "iat", "delay_import", "clr", "reserved",
)


def parse(data):
    def value(fmt, pos):
        return struct.unpack_from("<" + fmt, data, pos)[0]

    if data[:2] != b"MZ":
        raise ValueError("Missing DOS header")
    pe = value("I", 60)
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Missing PE signature")
    opt = pe + 24
    magic = value("H", opt)
    if magic not in (0x10b, 0x20b):
        raise ValueError("Unsupported optional header")
    wide = magic == 0x20b
    directory_offset = opt + (112 if wide else 96)
    count = value("I", opt + (108 if wide else 92))
    if count > 16:
        raise ValueError("Unexpected fixture directory count")
    section_table = opt + value("H", pe + 20)
    sections = []
    fields = {}
    for name, offset, fmt in (
        ("Machine", 4, "H"), ("NumberOfSections", 6, "H"),
        ("TimeDateStamp", 8, "I"), ("PointerToSymbolTable", 12, "I"),
        ("NumberOfSymbols", 16, "I"), ("SizeOfOptionalHeader", 20, "H"),
        ("Characteristics", 22, "H"),
    ):
        fields["COFF." + name] = value(fmt, pe + offset)
    optional_fields = [
        ("Magic", 0, "H"), ("MajorLinkerVersion", 2, "B"), ("MinorLinkerVersion", 3, "B"),
        ("SizeOfCode", 4, "I"), ("SizeOfInitializedData", 8, "I"),
        ("SizeOfUninitializedData", 12, "I"), ("AddressOfEntryPoint", 16, "I"),
        ("BaseOfCode", 20, "I"), ("SectionAlignment", 32, "I"),
        ("FileAlignment", 36, "I"), ("MajorOperatingSystemVersion", 40, "H"),
        ("MinorOperatingSystemVersion", 42, "H"), ("MajorImageVersion", 44, "H"),
        ("MinorImageVersion", 46, "H"), ("MajorSubsystemVersion", 48, "H"),
        ("MinorSubsystemVersion", 50, "H"), ("Win32VersionValue", 52, "I"),
        ("SizeOfImage", 56, "I"), ("SizeOfHeaders", 60, "I"), ("CheckSum", 64, "I"),
        ("Subsystem", 68, "H"), ("DllCharacteristics", 70, "H"),
    ]
    optional_fields += ([("ImageBase", 24, "Q")] if wide else
                        [("BaseOfData", 24, "I"), ("ImageBase", 28, "I")])
    for n, name in enumerate(("SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit")):
        optional_fields.append((name, 72 + n * (8 if wide else 4), "Q" if wide else "I"))
    optional_fields += [("LoaderFlags", 104 if wide else 88, "I"),
                        ("NumberOfRvaAndSizes", 108 if wide else 92, "I")]
    for name, offset, fmt in optional_fields:
        fields["Optional." + name] = value(fmt, opt + offset)
    directories = {}
    for n in range(count):
        name = DIRECTORY_NAMES[n]
        directories[name] = (value("I", directory_offset + n * 8),
                             value("I", directory_offset + n * 8 + 4))
        fields["Directory." + name] = list(directories[name])
    for n in range(fields["COFF.NumberOfSections"]):
        pos = section_table + n * 40
        section = {"name": data[pos:pos + 8].rstrip(b"\0").decode("ascii"),
                   "rva": value("I", pos + 12), "raw_size": value("I", pos + 16),
                   "raw_offset": value("I", pos + 20), "header": data[pos:pos + 40]}
        sections.append(section)

    def offset(rva):
        if rva < fields["Optional.SizeOfHeaders"]:
            return rva
        for section in sections:
            delta = rva - section["rva"]
            if 0 <= delta < section["raw_size"]:
                return section["raw_offset"] + delta
        raise ValueError(f"RVA 0x{rva:x} has no raw data")

    def string(rva):
        start = offset(rva)
        return data[start:data.index(0, start)].decode("ascii")

    imports = []
    rva, size = directories.get("import", (0, 0))
    if rva:
        pos = offset(rva)
        while any(data[pos:pos + 20]):
            original_thunk, _, _, name, first_thunk = struct.unpack_from("<IIIII", data, pos)
            pointer = offset(original_thunk or first_thunk)
            width, fmt, ordinal_bit = (8, "Q", 1 << 63) if wide else (4, "I", 1 << 31)
            symbols = []
            while value(fmt, pointer):
                thunk = value(fmt, pointer)
                symbols.append({"ordinal": thunk & 0xffff} if thunk & ordinal_bit else
                               {"name": string(thunk + 2), "hint": value("H", offset(thunk))})
                pointer += width
            imports.append({"dll": string(name), "symbols": symbols})
            pos += 20
    exports = None
    export_rva, export_size = directories.get("export", (0, 0))
    if export_rva:
        pos = offset(export_rva)
        base, function_count, name_count, functions, names, ordinals = struct.unpack_from("<IIIIII", data, pos + 16)
        names_by_index = {}
        for n in range(name_count):
            index = value("H", offset(ordinals) + n * 2)
            names_by_index.setdefault(index, []).append(string(value("I", offset(names) + n * 4)))
        symbols = []
        for n in range(function_count):
            function_rva = value("I", offset(functions) + n * 4)
            symbols.append({"ordinal": base + n, "rva": function_rva,
                            "names": names_by_index.get(n, []),
                            "forwarder": string(function_rva) if export_rva <= function_rva < export_rva + export_size else None})
        exports = {"dll": string(value("I", pos + 12)), "symbols": symbols}
    relocations, blocks, relocation_issues = [], [], []
    rva, size = directories.get("base_relocation", (0, 0))
    if rva:
        pos, end = offset(rva), offset(rva) + size
        while pos < end:
            if end - pos < 8:
                relocation_issues.append(f"{end - pos} trailing bytes do not form a relocation block: {data[pos:end].hex()}")
                break
            page, block_size = struct.unpack_from("<II", data, pos)
            if block_size < 8 or block_size % 2 or pos + block_size > end:
                relocation_issues.append(f"Invalid relocation block at file offset 0x{pos:x}: size={block_size}")
                break
            entries = [value("H", n) for n in range(pos + 8, pos + block_size, 2)]
            blocks.append({"page": page, "size": block_size,
                           "padding_entries": sum(entry >> 12 == 0 for entry in entries)})
            relocations.extend((entry >> 12, page + (entry & 0xfff)) for entry in entries if entry >> 12)
            pos += block_size
    header_size = fields["Optional.SizeOfHeaders"]
    table_end = section_table + 40 * len(sections)
    regions = {
        "dos_header": data[:64], "dos_stub_and_rich": data[64:pe],
        "pe_signature": data[pe:pe + 4], "coff": data[pe + 4:opt],
        "optional_fixed": data[opt:directory_offset],
        "data_directories": data[directory_offset:directory_offset + 8 * count],
        "section_table": data[section_table:table_end],
        "header_padding": data[table_end:header_size], "all_headers": data[:header_size],
    }
    return {"fields": fields, "sections": sections, "imports": imports, "exports": exports,
            "relocations": sorted(relocations), "relocation_blocks": blocks,
            "relocation_issues": relocation_issues, "regions": regions}


def differences(a, b):
    return sum(x != y for x, y in zip(a, b)) + abs(len(a) - len(b))


def compare(original, restored):
    a, b = parse(original), parse(restored)
    fields = {key: [a["fields"].get(key), b["fields"].get(key)]
              for key in sorted(a["fields"].keys() | b["fields"].keys())
              if a["fields"].get(key) != b["fields"].get(key)}
    section_changes = []
    for n, (sa, sb) in enumerate(zip(a["sections"], b["sections"])):
        original_raw = original[sa["raw_offset"]:sa["raw_offset"] + sa["raw_size"]]
        restored_raw = restored[sb["raw_offset"]:sb["raw_offset"] + sb["raw_size"]]
        section_changes.append({"index": n, "names": [sa["name"], sb["name"]],
                                "header_equal": sa["header"] == sb["header"],
                                "raw_differences": differences(original_raw, restored_raw)})
    reloc_a, reloc_b = set(a["relocations"]), set(b["relocations"])
    return {
        "sizes": [len(original), len(restored)],
        "byte_differences": differences(original, restored),
        "header_region_differences": {name: differences(data, b["regions"][name])
                                      for name, data in a["regions"].items()},
        "field_changes": fields, "sections": section_changes,
        "exports_equal": a["exports"] == b["exports"],
        "exports": [a["exports"], b["exports"]],
        "imports_equal": a["imports"] == b["imports"],
        "imports": [a["imports"], b["imports"]],
        "relocations_equal": a["relocations"] == b["relocations"],
        "relocations_removed": sorted(reloc_a - reloc_b),
        "relocations_added": sorted(reloc_b - reloc_a),
        "relocation_blocks": [a["relocation_blocks"], b["relocation_blocks"]],
        "relocation_issues": [a["relocation_issues"], b["relocation_issues"]],
    }


if __name__ == "__main__":
    import argparse
    import json
    from pathlib import Path
    import sys

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("original", type=Path)
    parser.add_argument("restored", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(compare(args.original.read_bytes(), args.restored.read_bytes()), indent=2))
    except (OSError, ValueError, struct.error) as error:
        sys.exit(str(error))
