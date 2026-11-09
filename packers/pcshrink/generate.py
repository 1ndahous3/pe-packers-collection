"""Generate PCShrink 0.71 beta fixtures on Windows x64/WOW64.

Packer: https://ftpmirror.infania.net/pub/pc/pack/pcsnk071.zip (pcshrink.exe).
The distribution omits its required aplib.dll. Retained dependency is aPLib 0.26b:
https://jeyndoe.github.io/edump/pages/files/51c6_19.06.2008_CRACKLAB.rU.tgz
Extract APLIB.DLL beside pcshrink.exe. Its embedded banner identifies 0.26b and
_aP_pack@20 matches the old five-argument ABI. aPLib 0.44 opens the GUI but crashes
while packing; do not substitute newer libraries. Original GUI advertises aPLib
0.22. Our successful results use 0.26b, not a claimed recreation of that original
combination. Public archives are linked, not retained. No packer source was found.

  python packers/pcshrink/generate.py --output C:/Temp/pcshrink-new
  python packers/pcshrink/generate.py --verify-only
  python packers/pcshrink/generate.py --probe-failed --output C:/Temp/pcshrink-probe

Launch pcshrink.exe, set its filename edit and press OK with explicit GUI
settings in gui.py. Direct filename arguments can be misparsed for some paths. Input is changed in place. Profiles merge/no-merge differ only
in section merging. Resource restructuring is enabled; export compression and
backups are off. A baseline has no resources, so resource modes are not tested.

Only NX_COMPAT (0x100) is cleared in temporary x86 EXE inputs. Prepared inputs must
pass normal/wait/secret checks before packing. Original code/data/other flags stay
unchanged. Raw packed EXEs fault; clearing only ASLR also fails. No packed-output
patch is applied. The GUI's success dialog says 0.70 although its main window and
included manual identify 0.71 beta.

--probe-failed packs raw x86 EXE, DLL and both amd64 inputs. Raw EXE and x86 DLL
must fail bounded runtime checks; the latter reports DLL initialization failure,
even with ASLR/DEP/NO_SEH flags cleared. amd64 EXE raises illegal instruction;
amd64 DLL crashes the packer and leaves partial output, which is not executed.
All failures remain temporary. The tool and fixtures use one-process jobs.
"""
import argparse
import importlib.util
from pathlib import Path
import shutil
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
GUI = load('pc_driver', PACKER / 'gui.py')
HASHES = {'aplib.dll': 'd6343acad6aff1c40c964add00b654ce215a4da5502dde73574a3046ef52e071', 'pcshrink.exe': '95816844ea386bf21201011957c050c3318c707e9d82eb5a19940c1ec3bddc1d'}


def prepare(data, clear):
    result = bytearray(data); nt = struct.unpack_from('<I', result, 60)[0]
    pos = nt + 24 + 70
    struct.pack_into('<H', result, pos, struct.unpack_from('<H', result, pos)[0] & ~clear)
    return bytes(result)


def expect_failure(path, arch, kind):
    try:
        CHECK.normal(path, arch, kind)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f'{arch}/{kind}: expected failure: {error}', flush=True)
    else:
        raise ValueError('Negative probe unexpectedly worked')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--probe-failed', action='store_true')
    args = parser.parse_args()
    binaries = PACKER / 'tools/0.71/bin'
    for name, digest in HASHES.items():
        CHECK.require(CHECK.sha256(binaries / name) == digest, 'Unexpected tool/dependency: ' + name)
    output = (args.output or PACKER / 'packed-fixtures/0.71').resolve(); saved = {}
    with tempfile.TemporaryDirectory(prefix='pe-pcshrink-', ignore_cleanup_errors=True) as temp:
        work = Path(temp)
        for name in HASHES:
            shutil.copyfile(binaries / name, work / name)
        tool = work / 'pcshrink.exe'
        source, _ = CHECK.reference('x86', 'exe')
        for profile, merge in (('merge', True), ('no-merge', False)):
            target = output / f'fixture-x86-exe/{profile}.exe'
            if args.verify_only:
                CHECK.verify(target, 'x86', 'exe'); continue
            CHECK.require(not target.exists(), 'Use --verify-only or a fresh --output')
            sample = work / (profile + '.exe'); sample.write_bytes(prepare(source.read_bytes(), 0x100))
            CHECK.verify(sample, 'x86', 'exe')
            _, messages = GUI.pack(tool, sample, merge)
            CHECK.require(any('Successfully compressed!' in x for x in messages), 'Packing failed: ' + repr(messages))
            CHECK.verify(sample, 'x86', 'exe'); saved[target] = sample.read_bytes()
        if args.probe_failed and not args.verify_only:
            for arch, kind in (('x86', 'exe'), ('x86', 'dll'), ('amd64', 'exe'), ('amd64', 'dll')):
                source, _ = CHECK.reference(arch, kind)
                sample = work / f'negative-{arch}.{kind}'
                sample.write_bytes(prepare(source.read_bytes(), 0x540 if kind == 'dll' and arch == 'x86' else 0))
                status, messages = GUI.pack(tool, sample)
                if arch == 'amd64' and kind == 'dll':
                    CHECK.require(status == 0xc0000005, 'Unexpected amd64 DLL packing result')
                else:
                    CHECK.require(any('Successfully compressed!' in x for x in messages), 'Unexpected packing result')
                    expect_failure(sample, arch, kind)
                CHECK.reference(arch, kind)
        CHECK.reference('x86', 'exe')
        for target, data in saved.items():
            CHECK.publish(data, target)
    if work.exists():
        print(f'Windows still holds a temporary image; remove later: {work}', flush=True)


if __name__ == '__main__':
    main()
