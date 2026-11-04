; MASM equivalent of the upstream Loader/loaderstructs.h; replaces h2inc.
KERNEL_IAT STRUCT
 pGetModuleHandleA DWORD ?
 pGetProcAddress DWORD ?
 pVirtualAlloc DWORD ?
 pVirtualFree DWORD ?
 pVirtualProtect DWORD ?
 dwNullEntry DWORD ?
KERNEL_IAT ENDS
LOADER_STRUCT STRUCT
 UNION
  dwNegatedLoaderRva DWORD ?
  dwImageBase DWORD ?
 ENDS
 dwUnpackMemSize DWORD ?
 dwTotalMemSize DWORD ?
 dwOepDelta DWORD ?
 dwOrigTLSIndex DWORD ?
 pUnpack DWORD ?
 pSectionData DWORD ?
 pHeader DWORD ?
 pImports DWORD ?
 pRelocations DWORD ?
 pTLSIndex DWORD ?
 UNION
  dwNegatedImageBase DWORD ?
  dwImageDelta DWORD ?
 ENDS
 pKernelIAT DWORD ?
LOADER_STRUCT ENDS
