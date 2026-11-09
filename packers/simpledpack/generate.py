"""Generate SimpleDpack 0.5.3 fixtures (Windows x64/WOW64, Python).

Official release: https://github.com/YuriSizuku/win-SimpleDpack/releases/tag/v0.5.3
Download SimpleDpack.exe, SimpleDpack64.exe, simpledpackshell.dll and
simpledpackshell64.dll from its assets into tools/0.5.3/bin. The tool locates its
shell DLL relative to the working directory. Source tag v0.5.3 is revision
d802b0efbb63a8099d7a1c9b137c9c13ec4d2e77; it has a VS2019 solution. We use the
official binaries; rebuilding upstream was not tested. Both tool architectures
and packed outputs need the matching VC++ 2015-2022 runtime/UCRT installed.

  python packers/simpledpack/generate.py --output C:/Temp/simpledpack-new
  python packers/simpledpack/generate.py --verify-only
  python packers/simpledpack/generate.py --probe-failed --output C:/Temp/simpledpack-probe

From the tool directory:
  SimpleDpack.exe <temporary-x86-input.exe> <output.exe>
  SimpleDpack64.exe <temporary-amd64-input.exe> <output.exe>
No input or output patch. Standard helper checks normal/wait/secret behavior.
--probe-failed also attempts DLLs. Their export directory points into compressed
bytes; bounded rundll32 runs fail. The x86 packer can fault after writing its DLL
output. These outputs are never retained. Tool copies and all inputs are temporary.
Use --verify-only or a fresh --output: different artifacts are never replaced.
"""
import argparse
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
spec = importlib.util.spec_from_file_location('checks', ROOT / 'tools/fixture_checks.py')
CHECK = importlib.util.module_from_spec(spec); spec.loader.exec_module(CHECK)
HASHES = {'SimpleDpack.exe': 'dc30566e9ea708cfbdd4b92f746853fbfd4135531857ef330c1bbd0d60dc5f9c', 'SimpleDpack64.exe': 'bcc09e15ce62452e0c63dba53d2250d760f31a103285b031fdd77ec6c3dfab01', 'simpledpackshell.dll': 'd62fd8f1b7dd543e5d7ae8f41bc3e10dab7bb0f6ac5f18ca7cc58415eb99cd96', 'simpledpackshell64.dll': 'a82936fdd5aae850255fd93a326de5fe82754727bddef2a4bbb2152861ed87de'}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--probe-failed', action='store_true')
    args = parser.parse_args()
    binaries = PACKER / 'tools/0.5.3/bin'
    for name, digest in HASHES.items():
        CHECK.require(CHECK.sha256(binaries / name) == digest, 'Unexpected tool/dependency: ' + name)
    output = (args.output or PACKER / 'packed-fixtures/0.5.3').resolve()
    outputs = {}
    with tempfile.TemporaryDirectory(prefix='pe-simpledpack-', ignore_cleanup_errors=True) as temp:
        work = Path(temp)
        for name in HASHES:
            shutil.copyfile(binaries / name, work / name)
        for arch in ('x86', 'amd64'):
            tool = work / ('SimpleDpack.exe' if arch == 'x86' else 'SimpleDpack64.exe')
            for kind in (('exe', 'dll') if args.probe_failed and not args.verify_only else ('exe',)):
                source, ref = CHECK.reference(arch, kind)
                target = output / f'fixture-{arch}-{kind}' / f'default.{kind}'
                if args.verify_only:
                    CHECK.verify(target, arch, kind); continue
                CHECK.require(not target.exists(), 'Use --verify-only or a fresh --output')
                sample = work / f'fixture-input-{arch}.{kind}'; sample.write_bytes(source.read_bytes())
                packed = work / f'packed-{arch}.{kind}'
                result = CHECK.run([tool, sample, packed], work, 30)
                CHECK.require(packed.exists(), 'No packed output')
                if kind == 'exe':
                    CHECK.require(result.returncode == 0, 'Packer failed')
                    CHECK.verify(packed, arch, kind)
                    outputs[target] = packed.read_bytes()
                else:
                    try:
                        CHECK.normal(packed, arch, kind)
                    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
                        print(f'{arch} DLL: expected runtime failure: {error}', flush=True)
                    else:
                        raise ValueError('DLL probe unexpectedly passed; review support')
                CHECK.require(CHECK.sha256(sample) == ref['sha256'], 'Temporary input changed')
                CHECK.reference(arch, kind)
        for target, data in outputs.items():
            CHECK.publish(data, target)
    if work.exists():
        print(f'Windows still holds a temporary image; remove later: {work}', flush=True)


if __name__ == '__main__':
    main()
