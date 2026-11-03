# Sources

Public collections, inventories, and research resources used to seed this index:

- [Dataset of Packed PE](https://github.com/packing-box/dataset-packed-pe) — Packed and unpacked PE samples with corrected labels and outliers. Sanitization concerns dataset quality, not a guarantee that samples are harmless.
- [PackingData](https://github.com/chesvectain/PackingData) — Original corpus. Some samples are mislabeled; consult the corrected fork and the FFRI evaluation.
- [Tuts4You UnpackMe Collection (2016)](https://forum.tuts4you.com/files/file/1314-tuts-4-you-unpackme-collection-2016/) — UnpackMe samples covering many packers and versions, primarily PE32 with a smaller PE64 section. Downloads require an account.
- [Packing Box](https://github.com/packing-box/docker-packing-box) — Dataset generation and management tools. Its [packer configuration](https://github.com/packing-box/docker-packing-box/blob/main/src/conf/packers.yml) provides a machine-readable inventory; listed integrations may be incomplete or unavailable.
- [Unipacker samples](https://github.com/unipacker/unipacker/tree/master/Sample) — Fixtures accompanying a Unicorn-based unpacker. Most are real malware, according to the sample README. Sample presence does not imply unpacker support.
- [Packware](https://github.com/ucsb-seclab/packware) — Research data and experiment code, including links between packed samples and originals. Binaries are available by contacting the authors.
- [Awesome Executable Packing](https://github.com/packing-box/awesome-executable-packing) — Directory of packers, unpackers, datasets, and publications.
- [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) — The [PE signature database](https://github.com/horsicq/Detect-It-Easy/tree/0b5454f21eea920a4444ae5d513da969555a221a/db/PE) provides family names, detection logic, version labels, and project references. Detection alone does not prove an exact version or successful unpacking.
- [Corkami PE examples](https://github.com/corkami/pocs/tree/master/PE) — Unusual PE structures for testing loaders, emulators, and reconstruction.
- [FFRI PackerDetectionToolEvaluation](https://github.com/FFRI/PackerDetectionToolEvaluation) — Detector evaluation, PackingData label corrections, and references to [RCE_Lab](https://github.com/apuromafo/RCE_Lab) UnpackMe samples.

Sample contents and availability must be checked when importing a case.

## Additional catalogs and acquisition leads

Awesome links to these collections without listing all their contents. They can supply versions, manuals, archive names and unpacking methods absent from its packer entries.

| Source | Useful material and limits |
| --- | --- |
| [Assiste](https://web.archive.org/web/20211017145403/https://assiste.com/Packer.html) | Historical names, authors and versions, including PKLite32. Mixes PE tools with DOS utilities, archivers, unpackers and malware labels; filter by payload and tool identity. |
| [ProTools](https://protools.narod.ru/packers.htm) | Historical product descriptions and download leads. Linked binaries were not verified. |
| [Defacto2 packers](https://web.archive.org/web/20240928172542/https://defacto2.net/f/a520164) and [unpackers](https://web.archive.org/web/20240214181649/https://defacto2.net/f/a218ab4?dosmachine=svga&dosspeed=max&dosutils=true) | Archive member names and documentation; much is DOS-oriented, and the unpacker listing is incomplete. A listing alone does not establish a retrievable PE tool. |
| [PE Compression Test](https://web.archive.org/web/20250427032942/http://pect.atspace.com/) | Versions, packing settings and output sizes. Executable validity was not checked consistently; this is a historical benchmark. |
| [OllyDbg scripts](https://github.com/xshows/ollydbg-script/tree/a6900722c747719ffe312dddd0ad2fa12b8ac97b) | OEP finding, import repair and unpacking references. Scripts were read as text; their applicability remains untested. |
| [EXEInfo-PE](https://github.com/ExeinfoASL/ASL) | Additional identity and version clues. Detector labels alone do not establish an available packing tool. |

Concrete search terms retained from the catalogs:

- Defacto2 archive directories: `32lite.02d-Oleg Prokhorov/`, `shrinker.34demo-blink/`.
- ProTools version labels: `Armadillo 1.83`, `CodeCrypt 0.164`, `Crunch 1.0`, `Ding Boy's PE-Lock 1.5b3`, `Fusion 1.0`, `LameCrypt 1.00 alpha`, `NeoLite 2.0`, `NFO 1.0`, `PCPEC alpha preview`, `PE Diminisher 0.1`, `PE password protector by SMT`, `PE-PROTECT 0.9 beta`, `PE-PaCK 1.0`, `PE-SHiELD 0.25`, `PECRYPT32 1.02`, `PELOCKnt 2.04`, `PKLite32 1.1`, `Shrinker 3.4`, `PE-Encrypter 2.0 by Stone`, `tElock 0.41c`, `VGCrypt 0.75`.
- PE Compression Test version labels: `bambam 0.01`, `exe32pack 1.38 / 1.42`, `ezip 1.0`, `JDPack 1.01`, `PCShrink 0.71`, `PE Quake 0.0.6`, `PolyEnE 0.01+`, `Thunderbolt 0.02`.

The [Packing Box configuration reviewed](https://github.com/packing-box/docker-packing-box/blob/91fd2865d3bcd620131ab126e906eb5a52c0ed67/src/conf/packers.yml) supplies installation and packing recipes for FSG, MEW, RLPack and tElock. Its integration results are upstream claims; its AinEXE description says DOS while the format field says PE32. ThinApp's documented build workflow also does not reproduce a legacy Thinstall stub automatically.

## Identity decisions

- **XComp / XPack:** related JoKo products share a cited download source in the [PIEtrace paper](https://www.cs.purdue.edu/homes/xyzhang/Comp/ase2013-kwon.pdf). Keep one family and record the actual tool per case. The DOS XPack attributed to Jauming Tseng is separate.
- **Code Virtualizer:** merge the Code Virtualizer and Oreans CodeVirtualizer labels. **DBPE / PE Lock Phantasm:** merge the Ding Boy labels based on the `dbpe12.zip` reference and overlapping versions; keep PELock and PELOCKnt separate.
- **Sentinel LDK, Protection Plus and VMProtect:** group their edition/SDK labels by product family. A managed edition or SDK signature alone does not prove native packing functionality.
- **Themida / WinLicense:** retain the shared family label; identify the actual product in each case. **Enigma Protector / Enigma Virtual Box:** retain separate protector and bundler entries.
- Keep nPack/NSPack, RLP/RLPack, North Star PE Shrinker/NSPack, the two ExeShield namesakes, BlindSpot Framework/legacy BlindSpot, Beria/Berio, Fish PE/FishPE Shield, and Obsidian/Obsidium projects separate pending provenance.
- Shared signature bytes do not establish aliases: Anskya Binder/MicroJoiner, AHpacker/ExE Pack and Inquartos/Yoda remain separate. PackLite is an unresolved benchmark label, not an established alias of PKLite32.

OllyDbg folder names can mislead: `NPack 1.1 OEP Finder` is under `NsPack/`; `SoftSentry/` also contains Stone's scripts; Gie-Protector is under `G!X Protector/`; FakeSigner is under `DotFix NiceProtect/`. The ExeShield script names ARM Protector 0.1 and does not resolve the ExeShield namesakes. Attribute scripts by their contents.

## Scope decisions

| Excluded material | Reason |
| --- | --- |
| Named malware-specific packers and generic malware labels | Outside the reusable PE tool inventory. |
| DOS/COM-only tools, data archivers, unpackers and compiler labels | Do not establish a tool that packs a native PE. Placement under DiE's `db/PE` is insufficient. |
| Managed-only protectors and CLR wrappers without an established native payload path | Require a different recovery target and validation criteria. |
| Script/language bundles and document/media viewers | Recover scripts, runtimes or embedded content rather than a pre-existing native PE. |
| Anti-cheat and licensing component signatures | Component detection alone does not establish a reusable packing envelope. |
| Signature masking and static-only obfuscation | Test detector robustness or deobfuscation without an established runtime unpacking layer. |
| Shellcode injection wrappers | Pack an added payload rather than the original application. |
| Generic or unresolved identities | Insufficient evidence for an independent packer family. |

Native licensing envelopes, code virtualization and bundling remain eligible. [Appacker](https://github.com/SerGreen/Appacker) can bundle native applications despite its managed implementation. [Ryujin](https://github.com/keowu/Ryujin) includes code encryption and virtualization; [Alcatraz](https://github.com/weak1337/Alcatraz) and [xObf](https://github.com/d35ha/xObf) were excluded as static transformations.

[Malware_HW2_b](https://github.com/Punfake/Malware_HW2_b) remains eligible because it documents packing arbitrary PE inputs. [Packed-Infected-PE](https://github.com/huykingsofm/Packed-Infected-PE) was excluded because it packs added MessageBox shellcode. Product names alone do not decide scope. PACE and SecuROM support/unpacking references do not establish access to a developer-side packing workflow.

## DiE research clues

The reviewed [PE database](https://github.com/horsicq/Detect-It-Easy/tree/0b5454f21eea920a4444ae5d513da969555a221a/db/PE) was filtered to `.sg` filenames containing `packer_`, `protector_`, `cryptor_`, `obfuscator_` or `joiner_`. This covered 451 rules, not the whole database or 451 distinct products. Direct rule links remain in the [index](README.md#packer-indexes).

A rule's `.2.sg` suffix is not a packer version. Signature bytes, labels and architecture predicates are research leads, not a complete support matrix. Prefer product documentation when assigning mechanisms: Crinkler is a compressing linker; PEBundle is an application bundler.

Potential fixture checks from the rules:

- Fatpack: native 64-bit/TLS checks and resource versus section payload storage.
- BoxedApp: TLS, sections, demo markers, modified stubs and bundled dependencies.
- Windows PE Packer: PE32 layout and modified section/import paths.
- AlushPacker: import order, Rich signature and packed-section checks.
- Code Virtualizer and ReWolf Virtualizer: code recovery criteria beyond decompression.

These clues have not been verified through local cases. The source review used the pinned DiE database above, [Awesome's Tools section](https://github.com/packing-box/awesome-executable-packing/blob/9e41a9b10b45535c1278259129ec8eaf287b8a42/README.md#wrench-tools), and the pinned Packing Box and OllyDbg links above.
