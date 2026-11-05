"""Generate verified WWPack32 1.20 EXE/DLL fixtures.

Acquisition / building
---------------------
Author: https://www.wwpack32.venti.pl/wwpack32_download.html
Download: https://www.sac.sk/download/pack/wwp32120.zip
Mirror: https://ftpmirror.infania.net/pub/pc/pack/wwp32120.zip
Demo: the author page's direct ZIP link returned 404; both mirrors supplied the same
archive (SHA256 ccde0dd4f71f54d51015c2085788ebeb4de60a627b84dcfc722d15e4e797c991).
No buildable sources were included or established. Use the original binary.

Extract without running SETUP.EXE, using 7-Zip in a temporary directory:
  7z x wwp32120.zip -odist
  7z x dist/WWPACK32.PAK -p6I6YnQh9s -oapp
Copy only app/wwpack.exe to tools/1.20-demo/bin/ beside this script. WWPACK32.PAK
is an encrypted RAR. The installer derives its extraction password by removing
the last two characters from SETUP.DAT's Password value and adding each remaining
character's one-based position to its character code. The resulting password
above opens the original archive with CRC validation. It is an archive password,
not a registration key. WWPACK.DOC in that archive is the author's manual.

Full / Ghosthunter: https://archive.org/details/cracklb-2010
Mirror: https://archive.org/details/crackl-b-sun-dvd-2010
ISO member: ANALYZE_L@B/Packers/WWPack32 1.20 Full.rar
Both Joliet catalogs yielded identical archives (SHA256
22248ba961c3b688dfdaedeb7f313668a5a95ce1dcda5daaf828d461b0a70d5b).
HTTP Range recovery: SUN_2010.iso bytes 1070518272-1070728904;
CRACKL@B_SUN_DVD_2010.iso bytes 1072998400-1073209032 (inclusive).
Require HTTP 206, matching Content-Range, length and archive hash; then 7z t/x.
The retained rare RAR is beside bin/ and contains only wwpack.exe. Its embedded
credit says "Cracked by Ghosthunter" and links kickme.to/teamc. No NFO or source
is included, so exact modifications versus a registered original are unknown.
The collection does not patch the tool itself.

Generation
----------
Requirements: Windows x64 with WOW64, an interactive desktop, Python 3.8+;
standard library only. From the collection root:
  python packers/wwpack32/generate.py --version 1.20-demo
  python packers/wwpack32/generate.py --version 1.20-full-ghosthunter
  python packers/wwpack32/generate.py --version 1.20-full-ghosthunter --kind dll --profile best
  python packers/wwpack32/generate.py --version 1.20-demo --output C:/Temp/wwpack-check
Repeat --profile, --arch or --kind to select multiple values.

The public demo rejects DLL compression and does not enable the documented
filename CLI; that command opens registration UI. gui.py drives the unchanged
GUI with level 0 (fastest) or 20 (best), automatic sections, resources enabled,
relocation stripping disabled, safe mode enabled and no signature. A startup
registry-write warning is acknowledged if present, followed by refreshing the
working folder. No elevation or registry permission change is required here.
Each tool run uses a private copy of wwpack.exe and a separate input directory.

Output compatibility fix
------------------------
Stock outputs keep NX_COMPAT but omit execute permission on their .WWP32 loader
section. Windows raises an execute access violation at entry. fix_loader() adds
only IMAGE_SCN_MEM_EXECUTE to that section. DYNAMIC_BASE, NX_COMPAT, relocation
data and compressed code remain unchanged. Inputs and the tool are not patched.
All retained files include this explicit header fix.
The Ghosthunter DLL also needs its base-relocation directory Size reduced to the
actual no-op block, excluding trailing zeros. The stale original size causes
rebased loading to fail before the stub runs. fix_dll_relocation_size() validates
this exact structure and changes only the directory Size. The packed loader can
then initialize the DLL at an alternate base; preferred and forced alternate
loads passed full secret-byte checks. DLL code, payload and mitigation flags
remain unchanged by these fixes.

Coverage / checks
-----------------
Require tool and original manifest hashes, source markers, original execution,
matching machine/magic/kind/exports, an unchanged packer-created .BAK, exact packed
stdout, exit zero, empty stderr and sustained wait readiness (DLL by name and
ordinal 4). The .text marker must be hidden; visibility of the other markers is reported, not treated as a
failure. Runtime checksums verify all secrets. Separate exact memory checks and
manual-section observations are documented in internals.md.

The demo supports x86 EXE; Ghosthunter also supports x86 DLL. Both reject amd64
EXE/DLL without modifying inputs. Unsupported cases are skipped before GUI launch.
TLS/resources and disk unpacking are unverified. Separate DLL rebasing checks are
described in internals.md; this generator does not force a load address.

Publish only fastest/best PE files under
packed-fixtures/<version>/fixture-x86-<kind>/. Different existing bytes are never
overwritten. Temporary originals, .BAK files and raw outputs are deleted. GUI startup/packing waits are
bounded in gui.py; normal execution times out after ten seconds, and the shared
wait checker terminates only its own test process.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
TOOLS = {
    '1.20-demo': '0c75b613b35e88a5f4ee7fd6ecf3e5fcfb3e47ec9710b91bcfa8badd08130eba',
    '1.20-full-ghosthunter': 'ac0f094830ceb90011f4157caab2f89989a52110cf9875606fb3a6968f299244',
}
PROFILES = {'fastest': 0, 'best': 20}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def execute(path, kind):
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    command = ([str(path)] if kind == 'exe' else
               [str(Path(os.environ['WINDIR'])/'SysWOW64/rundll32.exe'), './'+path.name+',RunFixture'])
    result = subprocess.run(command, cwd=path.parent, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=10, startupinfo=startup)
    require(result.returncode == 0 and not result.stderr and
            result.stdout.replace(b'\r\n', b'\n') == f'pe-fixture:basic-{kind}:ok\n'.encode('ascii'),
            f'Runtime failure: exit={result.returncode:#x}, stdout={result.stdout!r}, stderr={result.stderr!r}')


def fix_loader(raw):
    """Add only the execute flag to the sole .WWP32 section in this PE32 output."""
    data = bytearray(raw)
    require(data[:2] == b'MZ', 'Missing DOS header.')
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    opt = nt + 24
    require(data[nt:nt+4] == b'PE\0\0' and
            struct.unpack_from('<H', data, nt+4)[0] == 0x14c and
            struct.unpack_from('<H', data, opt)[0] == 0x10b, 'Unexpected PE architecture.')
    require(struct.unpack_from('<I', data, opt+64)[0] == 0, 'Unexpected nonzero checksum.')
    count = struct.unpack_from('<H', data, nt+6)[0]
    table = opt + struct.unpack_from('<H', data, nt+20)[0]
    matches = [table + i*40 for i in range(count)
               if data[table+i*40:table+i*40+8].rstrip(b'\0') == b'.WWP32']
    require(len(matches) == 1, 'Expected exactly one loader section.')
    position = matches[0] + 36
    require(struct.unpack_from('<I', data, position)[0] == 0xc0000040,
            'Unexpected loader flags; review the fix.')
    struct.pack_into('<I', data, position, 0xe0000040)
    return bytes(data)


def fix_dll_relocation_size(raw):
    """Trim this build's padded no-op relocation directory to its actual block."""
    data = bytearray(raw)
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    opt = nt + 24
    require(struct.unpack_from('<H', data, nt+22)[0] & 0x2000, 'Expected a DLL.')
    directory = opt + 96 + 5*8
    rva, size = struct.unpack_from('<II', data, directory)
    count = struct.unpack_from('<H', data, nt+6)[0]
    table = opt + struct.unpack_from('<H', data, nt+20)[0]
    sections = [table+i*40 for i in range(count)]
    owners = []
    for position in sections:
        section_rva, raw_size = struct.unpack_from('<II', data, position+12)
        if section_rva <= rva and rva+size <= section_rva+raw_size:
            owners.append(position)
    require(len(owners) == 1, 'Relocation directory does not fit one raw section.')
    section = owners[0]
    require(data[section:section+8].rstrip(b'\0') == b'.reloc', 'Unexpected relocation section.')
    start = struct.unpack_from('<I', data, section+20)[0] + rva - struct.unpack_from('<I', data, section+12)[0]
    require(start+size <= len(data) and size >= 8, 'Truncated relocation directory.')
    page, block_size = struct.unpack_from('<II', data, start)
    loader = next(p for p in sections if data[p:p+8].rstrip(b'\0') == b'.WWP32')
    require(page == struct.unpack_from('<I', data, loader+12)[0] and
            8 < block_size < size and block_size % 2 == 0, 'Unexpected relocation block.')
    entries = struct.unpack_from('<'+'H'*((block_size-8)//2), data, start+8)
    require(all(entry >> 12 == 0 for entry in entries) and
            not any(data[start+block_size:start+size]), 'Expected no-op entries and zero padding.')
    struct.pack_into('<I', data, directory+4, block_size)
    return bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', required=True, choices=TOOLS)
    parser.add_argument('--profile', action='append', choices=PROFILES)
    parser.add_argument('--arch', action='append', choices=['x86', 'amd64'])
    parser.add_argument('--kind', action='append', choices=['exe', 'dll'])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Windows x64 with WOW64 is required.')
    tool = PACKER/'tools'/args.version/'bin/wwpack.exe'
    require(tool.is_file() and digest(tool) == TOOLS[args.version], 'Missing or unexpected tool binary.')
    arches = list(dict.fromkeys(args.arch or ['x86', 'amd64']))
    kinds = list(dict.fromkeys(args.kind or ['exe', 'dll']))
    if 'amd64' in arches:
        print('amd64 EXE/DLL: rejected by this PE32 packer; skipped.')
    if args.version == '1.20-demo' and 'dll' in kinds:
        print('x86 DLL: explicitly unsupported by this demo; skipped.')
        kinds.remove('dll')
    if 'x86' not in arches or not kinds:
        print('No supported fixtures selected.')
        return
    gui = load_module('wwpack_gui', PACKER/'gui.py')
    pe = load_module('fixture_manifest', ROOT/'fixtures/scripts/manifest.py')
    wait = load_module('fixture_wait', ROOT/'fixtures/scripts/check_wait.py')
    folder = ROOT/'fixtures/bin/x86'
    artifacts = json.loads((folder/'manifest.json').read_text(encoding='utf-8'))['artifacts']
    verified = {}
    with tempfile.TemporaryDirectory(prefix='pe-wwpack32-') as temporary:
        work = Path(temporary)
        copied_tool = work/'wwpack.exe'
        shutil.copyfile(tool, copied_tool)
        for kind in kinds:
            ref = next(x for x in artifacts if x['id'] == f'basic-{kind}-x86')
            original = folder/ref['path']
            require(digest(original) == ref['sha256'], 'Shared original differs from manifest.')
            original_bytes = original.read_bytes()
            for marker in ref['secrets']:
                require(bytes.fromhex(marker['hex']) in original_bytes,
                        f'Original marker missing: {marker["id"]}')
            try:
                baseline = work/f'baseline.{kind}'
                baseline.write_bytes(original_bytes)
                execute(baseline, kind)
                info_original = pe.inspect_pe(baseline)
                for profile in dict.fromkeys(args.profile or PROFILES):
                    directory = work/f'{kind}-{profile}'
                    directory.mkdir()
                    target = directory/f'probe.{kind}'
                    target.write_bytes(original_bytes)
                    raw = gui.pack(copied_tool, target, PROFILES[profile])
                    info_raw = pe.inspect_pe(target)
                    for field in ('machine', 'optional_header', 'kind', 'exports',
                                  'dynamic_base', 'nx_compatible', 'relocations_size'):
                        require(info_raw[field] == info_original[field], f'Unexpected output {field}.')
                    packed = fix_loader(raw)
                    if kind == 'dll':
                        packed = fix_dll_relocation_size(packed)
                    target.write_bytes(packed)
                    visible = [m['id'] for m in ref['secrets'] if bytes.fromhex(m['hex']) in packed]
                    text_markers = [m for m in ref['secrets'] if m['section'] == '.text']
                    require(text_markers and all(m['id'] not in visible for m in text_markers),
                            'Code marker was not packed.')
                    execute(target, kind)
                    wait.check_fixture(target, 'x86', kind)
                    require(target.read_bytes() == packed, 'Execution modified output bytes.')
                    require(digest(copied_tool) == TOOLS[args.version], 'Temporary tool was modified.')
                    verified[Path(f'fixture-x86-{kind}')/f'{profile}.{kind}'] = packed
                    print(f'{kind}/{profile}: PASS, normal + wait; {len(original_bytes)} -> '
                          f'{len(packed)} bytes; visible markers: {", ".join(visible) or "none"}.', flush=True)
            finally:
                require(digest(original) == ref['sha256'], 'Shared original changed.')
                require(digest(tool) == TOOLS[args.version], 'Stored tool changed.')
    output = (args.output or PACKER/'packed-fixtures'/args.version).resolve()
    for name, data in verified.items():
        target = output/name
        require(not target.exists() or target.read_bytes() == data,
                f'Refusing different existing output: {target}')
    for name, data in verified.items():
        target = output/name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            with target.open('xb') as stream:
                stream.write(data)
    print(f'Published verified fixtures to {output}', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        raise SystemExit(1)
