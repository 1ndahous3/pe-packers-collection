"""Generate Squishy fixtures using Windows/Python standard library.

Download https://logicoma.io/squishy/releases/squishy-<version>.zip and keep
squishy-x64.exe in tools/<version>/bin. This is the HOST architecture: 0.1.3 packs
x86, 0.2.0 packs amd64. Public source/build instructions were not established.

  python packers/squishy/generate.py --version 0.1.3
  python packers/squishy/generate.py --version 0.2.0
  python packers/squishy/generate.py --version 0.2.0 --verify-only

Use --output <fresh-directory> to regenerate. --probe-failed repeats DLL and
opposite-architecture attempts, without publishing them. All children use bounded
one-process jobs. The input copy gains a deterministic 4 KiB read-only .pad
section: our tiny originals otherwise produce an underflowed output raw-section
size. Source bytes, behavior, markers and mitigation flags are preserved. Check
this prepared input before packing. Output bytes are never patched.

Command: squishy-x64.exe -i input.exe -o output.exe -d -p silent
-d validates both internal compression stages; it is not a disk unpacking option.
Runtime verification still requires normal/wait behavior and all secret checksums.
"""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
spec = importlib.util.spec_from_file_location('checks', ROOT / 'tools/fixture_checks.py')
CHECK = importlib.util.module_from_spec(spec); spec.loader.exec_module(CHECK)
HASHES = {'0.1.3': 'd00a5b533b6731f75c21a104a54f99d315a57fd73c130578bfa929a0a5a12193', '0.2.0': 'eedfd14e1f72d097239727836f792ed8de6c3ad9b0429f10cb6f73bc9425a600'}
ARCH = {'0.1.3': 'x86', '0.2.0': 'amd64'}


def prepare(raw):
    data = bytearray(raw)
    nt = struct.unpack_from('<I', data, 60)[0]
    count = struct.unpack_from('<H', data, nt + 6)[0]
    optional_size = struct.unpack_from('<H', data, nt + 20)[0]
    section = nt + 24 + optional_size + count * 40
    optional = nt + 24
    image_size, header_size = struct.unpack_from('<II', data, optional + 56)
    CHECK.require(section + 40 <= header_size and not any(data[section:section + 40]),
                  'No empty section-header slot')
    CHECK.require(len(data) % 512 == 0 and image_size % 4096 == 0, 'Unexpected alignment')
    noise = b''.join(hashlib.sha256(b'squishy-fixture-padding' + i.to_bytes(4, 'little')).digest()
                     for i in range(128))
    struct.pack_into('<8sIIIIIIHHI', data, section, b'.pad', 4096, image_size,
                     4096, len(data), 0, 0, 0, 0, 0x40000040)
    struct.pack_into('<H', data, nt + 6, count + 1)
    struct.pack_into('<I', data, optional + 56, image_size + 4096)
    initialized = struct.unpack_from('<I', data, optional + 8)[0]
    struct.pack_into('<I', data, optional + 8, initialized + 4096)
    return bytes(data) + noise


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', choices=HASHES, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--probe-failed', action='store_true')
    args = parser.parse_args()
    tool = PACKER / 'tools' / args.version / 'bin/squishy-x64.exe'
    CHECK.require(CHECK.sha256(tool) == HASHES[args.version], 'Unexpected tool')
    arch = ARCH[args.version]
    output = (args.output or PACKER / 'packed-fixtures' / args.version).resolve()
    target = output / f'fixture-{arch}-exe/padded.exe'
    if args.verify_only:
        CHECK.verify(target, arch, 'exe'); return
    CHECK.require(not target.exists(), 'Use --verify-only or fresh --output')
    cases = [(arch, 'exe')]
    if args.probe_failed:
        opposite = 'amd64' if arch == 'x86' else 'x86'
        cases += [(arch, 'dll'), (opposite, 'exe'), (opposite, 'dll')]
    for case_arch, kind in cases:
        source, ref = CHECK.reference(case_arch, kind)
        with tempfile.TemporaryDirectory(prefix='pe-squishy-', ignore_cleanup_errors=True) as temp:
            work = Path(temp); sample = work / f'fixture-input.{kind}'; packed = work / f'packed.{kind}'
            sample.write_bytes(prepare(source.read_bytes()) if case_arch == arch and kind == 'exe' else source.read_bytes())
            if case_arch == arch and kind == 'exe':
                CHECK.verify(sample, case_arch, kind)
            result = CHECK.run([tool, '-i', sample, '-o', packed, '-d', '-p', 'silent'], work, 120)
            if case_arch != arch:
                CHECK.require(result.returncode != 0 and not packed.exists() and
                              b'Input file is not a' in result.stderr, 'Unexpected architecture result')
                print(f'{case_arch}/{kind}: explicit architecture assertion'); continue
            CHECK.require(result.returncode == 0 and packed.exists() and
                          result.stdout.count(b'squish check OK') == 2, 'Packing/decompression check failed')
            if kind == 'dll':
                try:
                    CHECK.normal(packed, case_arch, kind)
                except (ValueError, OSError, subprocess.TimeoutExpired) as error:
                    print(f'{case_arch}/dll: {error}', flush=True)
                else:
                    raise ValueError('DLL now runs; review before publishing')
            else:
                CHECK.verify(packed, arch, kind)
                CHECK.publish(packed.read_bytes(), target)
            CHECK.require(CHECK.sha256(source) == ref['sha256'], 'Shared input changed')
        if work.exists():
            print(f'Windows still holds temporary files after child exit: {work}', file=sys.stderr)


if __name__ == '__main__':
    main()
