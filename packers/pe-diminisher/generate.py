"""Generate PE Diminisher 0.1 fixtures on Windows x64/WOW64.

Download https://ftpmirror.infania.net/pub/pc/pack/ped.zip and place ped.exe in
 tools/0.1/bin. The public archive is linked, not retained; no source was found.
GUI operation is in gui.py. Packing modifies the temporary input in place.

  python packers/pe-diminisher/generate.py --output C:/Temp/ped-new
  python packers/pe-diminisher/generate.py --verify-only
  python packers/pe-diminisher/generate.py --probe-failed --output C:/Temp/ped-probe

Clear only DYNAMIC_BASE and NX_COMPAT (0x140) on a temporary x86 EXE copy;
validate it before packing. Other flags, sections and fixture code stay unchanged.
Retain only a packed file passing normal, wait and all runtime secret checks.
No packed-output patch or host mitigation change is made.
--probe-failed checks raw and single-flag EXEs, prepared x86 DLL and both amd64
inputs. Failed outputs stay temporary. DLL export parsing fails because the
export-bearing section is compressed; runtime is tested separately in a bounded
one-process job. amd64 crashes the packer before a usable output is obtained.
"""
import argparse
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
CHECK = load('checks', ROOT / 'tools/fixture_checks.py')
GUI = load('ped_driver', PACKER / 'gui.py')
TOOL_HASH = 'cb6c5b337d31716f9fdb5517d6cce426436e46cf818ee91a98df667a22fef4f1'


def prepare(data, flags):
    result = bytearray(data); nt = struct.unpack_from('<I', result, 60)[0]; pos = nt + 94
    struct.pack_into('<H', result, pos, struct.unpack_from('<H', result, pos)[0] & ~flags)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--probe-failed', action='store_true')
    args = parser.parse_args()
    tool = PACKER / 'tools/0.1/bin/ped.exe'
    CHECK.require(CHECK.sha256(tool) == TOOL_HASH, 'Unexpected packer')
    output = (args.output or PACKER / 'packed-fixtures/0.1').resolve()
    target = output / 'fixture-x86-exe/default.exe'
    if args.verify_only:
        CHECK.verify(target, 'x86', 'exe'); return
    CHECK.require(not target.exists(), 'Use --verify-only or a fresh --output')
    with tempfile.TemporaryDirectory(prefix='pe-diminisher-', ignore_cleanup_errors=True) as temp:
        work = Path(temp); sample = work / 'fixture.exe'; source, _ = CHECK.reference('x86', 'exe')
        sample.write_bytes(prepare(source.read_bytes(), 0x140)); CHECK.verify(sample, 'x86', 'exe')
        _, status = GUI.pack(tool, sample)
        CHECK.require('Sucessfully Encrypted' in status, 'Packing failed: ' + status)
        CHECK.verify(sample, 'x86', 'exe'); packed = sample.read_bytes()
        if args.probe_failed:
            for arch, kind, flags in [('x86','exe',0), ('x86','exe',0x40), ('x86','exe',0x100),
                                       ('x86','dll',0x540), ('amd64','exe',0), ('amd64','dll',0)]:
                source, _ = CHECK.reference(arch, kind)
                negative = work / f'negative-{arch}-{flags}.{kind}'
                negative.write_bytes(prepare(source.read_bytes(), flags))
                code, status = GUI.pack(tool, negative)
                if arch == 'amd64':
                    CHECK.require(code == 0xc0000005, 'Unexpected amd64 packing result')
                else:
                    CHECK.require('Sucessfully Encrypted' in status, 'Unexpected packing result')
                    try:
                        CHECK.normal(negative, arch, kind)
                    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
                        print(f'{arch}/{kind}/{flags:#x}: expected failure: {error}', flush=True)
                    else:
                        raise ValueError('Negative probe unexpectedly passed')
                CHECK.reference(arch, kind)
        CHECK.reference('x86', 'exe'); CHECK.publish(packed, target)
    if work.exists():
        print(f'Windows still holds a temporary image; remove later: {work}', flush=True)


if __name__ == '__main__':
    main()
