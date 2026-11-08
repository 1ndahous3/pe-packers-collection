"""Extract NeoLite 2.0 trial's console and dependency without installation.

Download neolte20.zip from either public mirror:
  https://www.sac.sk/download/pack/neolte20.zip
  https://ftpmirror.infania.net/pub/pc/pack/neolte20.zip
Both supplied the same ZIP. From the collection root:
  python packers/neolite/prepare.py C:/Temp/neolte20.zip

The ZIP contains NeoLte20.EXE, a 16-bit Wise installer that cannot run on
Windows x64. This helper extracts two pinned raw DEFLATE members statically,
validates their stored CRC32 and SHA256, and saves only NeoLiteCli.exe and
Pecomp.dll in tools/2.0-trial/bin/. Existing different files are refused.
No installation, registry writes, network requests or third-party modules.
The public distribution includes manuals but no buildable packer sources;
there is no need to retain its ZIP or installer in the collection.
"""
import argparse
import hashlib
from pathlib import Path
import struct
import zipfile
import zlib

VERSION = '2.0-trial'
ZIP_HASH = '7647b7d5a565be9c938289de25509c35e9b7be9f9f10bebe8240543d3f01fd23'
MEMBERS = {
    'NeoLiteCli.exe': (0x48872, 41088, '5d02e4408ed6e481da69a0e2cb044cd49cad24ca630abe12d11d95265e388c1e'),
    'Pecomp.dll': (0x7d09c, 119762, 'ede105c855d9eb928b13a131ab906a4750a2b263538fab0638dcf071df721efa'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('archive', type=Path)
    args = parser.parse_args()
    require(hashlib.sha256(args.archive.read_bytes()).hexdigest() == ZIP_HASH,
            'Unexpected ZIP; review the distribution before extracting it.')
    with zipfile.ZipFile(args.archive) as archive:
        installer = archive.read('NeoLte20.EXE')  # ZIP CRC is checked too.
    outputs = {}
    for name, (offset, size, digest) in MEMBERS.items():
        stream = zlib.decompressobj(-15)
        data = stream.decompress(installer[offset:], size + 1)
        require(stream.eof and len(data) == size, 'Incomplete or oversized member: ' + name)
        end = len(installer) - len(stream.unused_data)
        require(struct.unpack_from('<I', installer, end)[0] == zlib.crc32(data), 'CRC mismatch: ' + name)
        require(hashlib.sha256(data).hexdigest() == digest, 'Hash mismatch: ' + name)
        target = Path(__file__).resolve().parent/'tools'/VERSION/'bin'/name
        require(not target.exists() or target.read_bytes() == data, 'Refusing to replace: ' + str(target))
        outputs[target] = data
    for target, data in outputs.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            with target.open('xb') as stream:
                stream.write(data)
        print(target)


if __name__ == '__main__':
    main()
