#!/usr/bin/env python3

FLOWER_MODULES = [
    "ntdll.dll",
    "kernel32.dll",
]

FLOWER_FUNCS = [
    # forwarded functions handling
    "LdrGetProcedureAddress",
    "LoadLibraryW",
    "LocalAlloc",
    "LocalFree",
    "VirtualAlloc",
    "VirtualProtect",
    "WaitForSingleObjectEx",
    "SystemFunction032",
    "RtlMoveMemory",

    "RtlZeroMemory",
    "RtlAllocateHeap",
    "RtlFreeHeap",
    "RtlExitUserThread",
    "RtlCaptureContext",
    "NtCreateEvent",
    "NtSetEvent",
    "NtFreeVirtualMemory",
    "NtContinue",
    "NtClose",
    "NtDuplicateObject",
    "NtWaitForSingleObject",
    "NtAllocateVirtualMemory",
    "NtGetContextThread",
    "NtSetContextThread",
    "VirtualFree",

    ##
    ## EKKO
    ##
    "RtlCreateTimer",
    "RtlCreateTimerQueue",
    "RtlDeleteTimerQueue",

    ##
    ## ZILEAN
    ##
    "RtlRegisterWait",

    ##
    ## FOLIAGE
    ##
    "NtQueueApcThread",
    "NtCreateThreadEx",
    "NtTerminateThread",
    "NtTestAlert",
    "RtlUserThreadStart",
    "NtAlertResumeThread",
    "ConvertThreadToFiberEx",
    "ConvertFiberToThread",
    "CreateFiberEx",
    "SwitchToFiber",
    "DeleteFiber",

    # to start the ROP chain
    "NtSignalAndWaitForSingleObject",

    # debug output
    "printf"
]


def fnv1a_32(string: str) -> str:
    """
    returns the hex representation of a given input string
    after running through fnv hash algo
    """
    hash = 0x811c9dc5
    fnv_prime = 0x01000193
    for char in string.upper():
        hash = hash ^ ord(char)
        hash = hash * fnv_prime
        hash &= 0xffffffff  # wrapping math

    return hex(hash)


if __name__ in '__main__':
    max_len = max(len(func) for func in FLOWER_FUNCS)
    for mod in FLOWER_MODULES:
        padding = ' ' * (max_len - len(mod) + 2)
        print(f"#define H_MODULE_{mod.upper().rsplit('.')[0]} {padding} {fnv1a_32(mod)}")

    print("")

    for func in FLOWER_FUNCS:
        padding = ' ' * (max_len - len(func))
        print(f"#define H_FUNC_{func.upper()} {padding} {fnv1a_32(func)}")
