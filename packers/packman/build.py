"""Build a collection CLI and plugins from the official Packman 1.0 source.

Requirements: Windows, Python 3.8+, 7-Zip, CMake 3.24+, Visual Studio 2022 with
MSVC v143 x86 tools and a Windows SDK. Run from any directory:
  python packers/packman/build.py
  python packers/packman/build.py --archive C:/Downloads/packman.source-1.0.rar
  python packers/packman/build.py --output C:/Temp/packman-bin

Official source:
https://sourceforge.net/projects/packmanpacker/files/1.0.0.0/packman.source-1.0.rar/download
The helper tries SourceForge's download redirect and the deac-riga mirror,
verifies the archive hash, extracts and builds in a temporary directory, then
publishes only packman-cli.exe, aPLib.dll and lzma.dll. Archives, upstream
sources and build intermediates are not retained. Different existing binaries
are never overwritten; use --output for a new compiler/build.

adapter/ supplies CMake, a small CLI and the MASM equivalent of loaderstructs.h.
No upstream source file is patched. CMake builds Release/Win32 with static CRT,
the bundled aPLib library, and the original LZMA Release definitions. It replaces
the obsolete h2inc step, provides the old IMAGE_SIZEOF_BASE_RELOCATION macro,
and disables SafeSEH metadata validation for the legacy assembly objects.
The GUI and its obsolete unicows dependency are not built. This is a local
source build, not the author's shipped executable. The retained tools were
built with MSVC 19.44.35229; another compiler may produce different hashes.
The fixture generator pins the retained build and does not trust an arbitrary
replacement. Independently validate a new build before updating those pins.

Direct CLI syntax:
  packman-cli.exe INPUT OUTPUT ABSOLUTE_PLUGIN_DLL normal|max-old|max-new
Use different input/output paths. The driver enables code filtering and overlay
retention, uses file alignment 512 and section name .PACKMAN, and leaves other
flags/resource filters zero. It explicitly rejects non-i386/PE32 and managed PE.
Exit codes: 0 packed, 2 usage/unsupported, 3 input, 4 plugin, 5 packer failure.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

PACKER = Path(__file__).resolve().parent
VERSION = '1.0-msvc2022'
SOURCE_SHA256 = '10a83eea57abae5da7f3af31ae95381d76b9899aa71dd8bee6f0293215a249fe'
URLS = (
    'https://downloads.sourceforge.net/project/packmanpacker/1.0.0.0/packman.source-1.0.rar',
    'https://deac-riga.dl.sourceforge.net/project/packmanpacker/1.0.0.0/packman.source-1.0.rar',
)
FILES = ('packman-cli.exe', 'aPLib.dll', 'lzma.dll')


def run(command):
    subprocess.run([str(x) for x in command], check=True, timeout=180,
                   stdin=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--seven-zip', type=Path, default=Path('C:/Program Files/7-Zip/7z.exe'))
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('Windows is required.')
    if not args.seven_zip.is_file():
        parser.error('7-Zip not found; supply --seven-zip PATH.')
    output = (args.output or PACKER/'tools'/VERSION/'bin').resolve()
    with tempfile.TemporaryDirectory(prefix='pe-packman-build-') as temporary:
        work = Path(temporary)
        archive = work/'source.rar'
        if args.archive:
            shutil.copyfile(args.archive, archive)
        else:
            for url in URLS:
                try:
                    with urllib.request.urlopen(url, timeout=30) as response:
                        archive.write_bytes(response.read())
                    break
                except (OSError, urllib.error.URLError) as error:
                    print(f'Download failed: {url}: {error}', file=sys.stderr)
            else:
                raise ValueError('Download failed; use --archive with the official source RAR.')
        if hashlib.sha256(archive.read_bytes()).hexdigest() != SOURCE_SHA256:
            raise ValueError('Source archive hash mismatch.')
        source = work/'source'
        run([args.seven_zip, 'x', archive, '-o'+str(source), '-y', '-bso0', '-bsp0'])
        build = work/'build'
        run(['cmake', '-S', PACKER/'adapter', '-B', build, '-G', 'Visual Studio 17 2022',
             '-A', 'Win32', '-DPACKMAN_SOURCE='+str(source/'Packman.source-1.0')])
        run(['cmake', '--build', build, '--config', 'Release', '--parallel'])
        artifacts = {name: (build/'bin/Release'/name).read_bytes() for name in FILES}
        # Check every destination before publishing any file.
        for name, data in artifacts.items():
            target = output/name
            if target.exists() and target.read_bytes() != data:
                raise ValueError(f'Refusing to overwrite different binary: {target}')
        output.mkdir(parents=True, exist_ok=True)
        for name, data in artifacts.items():
            target = output/name
            if not target.exists():
                with target.open('xb') as stream:
                    stream.write(data)
            print(f'{target.name}: SHA256 {hashlib.sha256(data).hexdigest()}')
        print(f'Published local Packman source build to {output}')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        raise SystemExit(1)
