#ifndef FLOWER_STUB_H
#define FLOWER_STUB_H

#include <windows.h>

/// stub definitions for the POC
///
/// as mentioned in [Stub.x64.asm] you should use the ones already existing
/// in your shellcode implant and edit the config (glorified define statements)
EXTERN_C PVOID FwRipStart();
EXTERN_C PVOID FwRipEnd();

#endif //FLOWER_STUB_H
