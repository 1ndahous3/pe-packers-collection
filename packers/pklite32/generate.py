"""Generate and verify PKLITE32 1.1 shareware fixtures.

Acquisition / building
----------------------
Download the same public SFX ZIP from either mirror:
  https://www.sac.sk/download/pack/pkl3211.exe
  https://ftpmirror.infania.net/pub/pc/pack/pkl3211.exe
Distribution SHA256: be52d2fce8f7d174ab7be1adaa0659d336a24ed232a9bbeb64048ffb8cb60b71
Extract without installation, keeping only PKLIT32W.EXE in tools/1.1-shareware/bin/:
  7z x C:/Temp/pkl3211.exe PKLIT32W.EXE -opackers/pklite32/tools/1.1-shareware/bin
No shell extension or bundled legacy IMAGEHLP.DLL is needed on the tested host;
the tool uses Windows' imagehlp.dll. The README/help identify release 1.1 even
though its generic VERSIONINFO says 1.0.0.1. No buildable packer source was found.
The public archive remains online; it is not stored in the collection.

Requirements / commands
-----------------------
Windows x64 with WOW64, an interactive desktop, 64-bit Python 3.8+; standard
library only. The shareware distribution is GUI-only; the documented CLI and
scripting interface belong to Professional and are not used here.
From the collection root:
  python packers/pklite32/generate.py --version 1.1-shareware
  python packers/pklite32/generate.py --version 1.1-shareware --verify-only
  python packers/pklite32/generate.py --version 1.1-shareware --output C:/Temp/pklite32-check
Repeat --arch x86|amd64 or --kind exe|dll to select cases. Different existing
artifacts are never replaced; loader metadata/checksum can vary between runs.
Use --verify-only for stored files or a fresh --output for regeneration.

Input preparation / packing
---------------------------
Unmodified small x86 fixtures are explicitly rejected because packing does not
significantly reduce their size. Generation first reproduces that rejection.
The retained padded-default profile then appends a 64 KiB zero-filled read-only
initialized .pad section to a temporary copy. Only the new section, section count,
SizeOfImage and SizeOfInitializedData are added/adjusted. Existing section bytes,
RVAs, code, exports, imports, secret locations and mitigation flags are preserved.
The padded input itself must pass execution and wait checks before compression.
This is a documented derived input, not an unmodified baseline packing result.

Run PKLIT32W.EXE <temporary-input>, restore Defaults, keep Preserve Relocation
Information checked and choose a separate Output File. Default section selection
compresses .text, .data, .secret and .pad; .rdata and .reloc are not selected.
gui.py verifies these selections and the GUI success result. No output/header fix
or packer patch is applied. Only the raw, verified packed PE is saved as
packed-fixtures/<version>/fixture-x86-<kind>/padded-default.<kind>.

Validation / cleanup
--------------------
Require pinned tool and shared manifest hashes, unchanged shared originals,
matching architecture/kind/exports, ASLR/DEP flags and relocation presence, all
original markers in the prepared input, exact runtime stdout/exit zero/empty stderr,
and --wait (EXE) or WaitFixture by name and ordinal 4 (DLL). Runtime checksums
verify all secrets; full-marker visibility on disk is reported separately.
The full matrix attempts amd64 too: require the explicit invalid-32-bit diagnostic,
no output and unchanged input. --verify-only checks retained x86 PEs without
repacking; it does not repeat the original-input or unsupported-input GUI probes.

The tool has no documented native disk decompression operation. External OEP
scripts are references; this helper does not establish exact disk recovery.
Only passing packed files are published after every selected case passes. Tool
copies, prepared inputs, backups and reports remain temporary. GUI settings are
restored and every launched process is bounded by the shared one-process job.
"""
import argparse
from contextlib import contextmanager
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
import time

sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
VERSION = '1.1-shareware'
TOOL_HASH = 'ebf01ae370b367da5ac15d36a26a8b75630617f2d1851e2371d33fe94feda36d'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def padded_input(original):
    data = bytearray(original)
    require(data[:2] == b'MZ', 'Expected MZ input.')
    nt = struct.unpack_from('<I', data, 60)[0]
    opt = nt + 24
    require(data[nt:nt+4] == b'PE\0\0' and struct.unpack_from('<H', data, nt+4)[0] == 0x14c
            and struct.unpack_from('<H', data, opt)[0] == 0x10b, 'Expected x86 PE32 input.')
    count = struct.unpack_from('<H', data, nt+6)[0]
    table = opt + struct.unpack_from('<H', data, nt+20)[0]
    names = [data[table+i*40:table+i*40+8].rstrip(b'\0') for i in range(count)]
    require(names == [b'.text', b'.rdata', b'.data', b'.secret', b'.reloc'], 'Review the changed fixture layout.')
    position = table + count*40
    header_size = struct.unpack_from('<I', data, opt+60)[0]
    require(position+40 <= header_size and not any(data[position:position+40]), 'No unused section-header slot.')
    section_alignment, file_alignment = struct.unpack_from('<II', data, opt+32)
    image_size = struct.unpack_from('<I', data, opt+56)[0]
    last = table + (count-1)*40
    raw_size, raw_offset = struct.unpack_from('<II', data, last+16)
    require(raw_offset+raw_size == len(data), 'Unexpected overlay or trailing data.')
    size = 65536
    require(section_alignment > 0 and file_alignment > 0 and image_size % section_alignment == 0
            and size % section_alignment == 0 and len(data) % file_alignment == 0
            and size % file_alignment == 0, 'Unexpected fixture alignment.')
    struct.pack_into('<8sIIIIIIHHI', data, position, b'.pad', size, image_size,
                     size, len(data), 0, 0, 0, 0, 0x40000040)
    struct.pack_into('<H', data, nt+6, count+1)
    struct.pack_into('<I', data, opt+56, image_size+size)
    struct.pack_into('<I', data, opt+8, struct.unpack_from('<I', data, opt+8)[0]+size)
    data.extend(bytes(size))
    require(data[header_size:len(original)] == original[header_size:], 'Existing section bytes changed.')
    return bytes(data)


def execute(path, arch, kind, isolated, wait):
    if kind == 'exe':
        command = [str(path)]
    else:
        windows = Path(os.environ['WINDIR'])
        host = windows/('SysWOW64' if arch == 'x86' else 'System32')/'rundll32.exe'
        command = [str(host), './'+path.name+',RunFixture']
    result = isolated.run(command, cwd=path.parent, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    require(result.returncode == 0 and not result.stderr and
            result.stdout.replace(b'\r\n', b'\n') == f'pe-fixture:basic-{kind}:ok\n'.encode('ascii'),
            f'Runtime exit={result.returncode:#x}, stdout={result.stdout!r}, stderr={result.stderr!r}')
    wait.check_fixture(path, arch, kind)


@contextmanager
def working_directory():
    temporary = tempfile.TemporaryDirectory(prefix='pe-pklite32-')
    path = Path(temporary.name).resolve()
    require(path.parent == Path(tempfile.gettempdir()).resolve() and path.name.startswith('pe-pklite32-'),
            'Unexpected temporary cleanup target.')
    try:
        yield path
    finally:
        # Win32 GUI teardown briefly retains the exited process's current directory.
        for attempt in range(20):
            try:
                temporary.cleanup()
                break
            except OSError as error:
                if getattr(error, 'winerror', None) != 32 or attempt == 19:
                    raise
                time.sleep(.1)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', required=True, choices=[VERSION])
    parser.add_argument('--arch', action='append', choices=['x86', 'amd64'])
    parser.add_argument('--kind', action='append', choices=['exe', 'dll'])
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    if os.name != 'nt' or struct.calcsize('P') != 8:
        parser.error('64-bit Python on Windows with WOW64 is required.')
    tool = PACKER/'tools'/args.version/'bin/PKLIT32W.EXE'
    require(tool.is_file() and digest(tool) == TOOL_HASH, 'Missing or unexpected packer binary.')
    pe = load('pklite_pe', ROOT/'fixtures/scripts/manifest.py')
    wait = load('pklite_wait', ROOT/'fixtures/scripts/check_wait.py')
    gui = load('pklite_owned_gui', PACKER/'gui.py')
    output = (args.output or PACKER/'packed-fixtures'/args.version).resolve()
    results, originals, failures = {}, {}, []
    with working_directory() as work:
        copied_tool = work/'PKLIT32W.EXE'
        shutil.copyfile(tool, copied_tool)
        for arch in dict.fromkeys(args.arch or ['x86', 'amd64']):
            folder = ROOT/'fixtures/bin'/arch
            refs = json.loads((folder/'manifest.json').read_text(encoding='utf-8'))['artifacts']
            for kind in dict.fromkeys(args.kind or ['exe', 'dll']):
                label = arch+'/'+kind
                ref = next(x for x in refs if x['id'] == f'basic-{kind}-{arch}')
                source = folder/ref['path']
                original = source.read_bytes()
                originals[source] = ref['sha256']
                require(digest(source) == ref['sha256'], 'Original differs from manifest.')
                case = work/(arch+'-'+kind)
                case.mkdir()
                local = case/f'original.{kind}'
                local.write_bytes(original)
                target = case/f'padded-default.{kind}'
                destination = output/f'fixture-{arch}-{kind}'/target.name
                try:
                    if args.verify_only and arch == 'amd64':
                        require(not destination.parent.exists(), 'Unexpected amd64 artifacts.')
                        print(label + ': unsupported; rejection not rerun in verify-only')
                        continue
                    execute(local, arch, kind, gui.ISOLATED, wait)
                    before = pe.inspect_pe(local)
                    require(all(bytes.fromhex(m['hex']) in original for m in ref['secrets']), 'Original marker missing.')
                    if not args.verify_only:
                        state, detail = gui.pack(copied_tool, local, target, padded=False)
                        if arch == 'amd64':
                            require(state == 'unsupported', 'Unexpected amd64 result: ' + detail)
                            print(label + ': UNSUPPORTED (explicit PE32 rejection; unchanged input, no output)')
                            continue
                        require(state == 'no-gain', 'Unexpected unmodified-input result: ' + detail)
                        print(label + ': unmodified baseline rejected (insufficient size reduction)')
                        prepared = case/f'padded.{kind}'
                        data = padded_input(original)
                        prepared.write_bytes(data)
                        require(all(bytes.fromhex(m['hex']) in data for m in ref['secrets']), 'Prepared marker missing.')
                        execute(prepared, arch, kind, gui.ISOLATED, wait)
                        state, detail = gui.pack(copied_tool, prepared, target, padded=True)
                        require(state == 'packed', 'Prepared input packing failed: ' + detail)
                        require(prepared.read_bytes() == data, 'Prepared input changed.')
                    else:
                        require(destination.is_file(), 'Missing fixture: ' + str(destination))
                        target.write_bytes(destination.read_bytes())
                    packed = target.read_bytes()
                    after = pe.inspect_pe(target)
                    for field in ('machine', 'optional_header', 'kind', 'exports', 'dynamic_base', 'nx_compatible'):
                        require(after[field] == before[field], 'Changed PE field: ' + field)
                    names = [s['name'] for s in after['sections']]
                    require('.pklstb' in names and '.pad' in names and after['relocations_size'] > 0,
                            'Missing packed layout/relocations.')
                    execute(target, arch, kind, gui.ISOLATED, wait)
                    require(target.read_bytes() == packed, 'Execution changed the packed file.')
                    visible = [m['id'] for m in ref['secrets'] if bytes.fromhex(m['hex']) in packed]
                    print(f'{label}: PASS padded-default; normal + wait; full markers visible={visible}; '
                          f'ASLR={after["dynamic_base"]}; DEP={after["nx_compatible"]}; bytes={len(packed)}')
                    results[destination] = packed
                except (ValueError, OSError, subprocess.TimeoutExpired) as error:
                    failures.append(label+': '+str(error))
                finally:
                    require(local.read_bytes() == original and digest(source) == ref['sha256'], 'Original changed.')
        for source, expected in originals.items():
            require(digest(source) == expected, 'Shared fixture changed.')
        require(digest(tool) == TOOL_HASH and digest(copied_tool) == TOOL_HASH, 'Packer binary changed.')
        require(not failures, 'No fixtures published.\n'+'\n'.join(failures))
        if not args.verify_only:
            for path, data in results.items():
                require(not path.exists() or path.read_bytes() == data, 'Refusing different output: '+str(path))
            for path, data in results.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    with path.open('xb') as stream:
                        stream.write(data)
    print('Verified existing fixtures.' if args.verify_only else
          'Published verified fixtures.' if results else 'No supported fixtures selected; no files saved.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
