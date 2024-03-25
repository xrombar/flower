#ifndef FLOWER_FLOWER_H
#define FLOWER_FLOWER_H

//
// only for the POC, use your own stub definitions (or dont lol)
//
#include <Stub.h>

#include <Native.h>
#include <windows.h>



//////////////////////////////////////////////////////////////////////////////////////////
// FLOWER Configuration

#define FW_DEBUG    1

#define SHC_START       FwRipStart
#define SHC_END         FwRipEnd
#define FUNCSEC         ".text$X"   // which section should we put the main shellcode functions

#define FW_BASE_OFS     0x10000
#define FW_SHIFT_OFS    0x1000

#define FLOWER_MAX_LEN  24      // how many CONTEXT structs should we get ready

//////////////////////////////////////////////////////////////////////////////////////////

#if FW_DEBUG == 1
#include <stdio.h>
#endif

#pragma region [macro]
//
// utils macros
//
#define D_API( x )  __typeof__( x ) * x;
#define FUNC        __attribute__( ( section( FUNCSEC ) ) )
#define FW_READONLY __attribute__( ( section( ".rdata" ) ) )
#define STATIC      static

//
// https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/include/core/SleepObf.h#L16
//
#define OBF_JMP( i, p ) \
    if ( Flags & FLOWER_GADGET_RAX ) { \
        Rop[ i ]->Rax = U_PTR( p );                    \
    } if ( Flags & FLOWER_GADGET_RBX ) {               \
        Rop[ i ]->Rbx = U_PTR( p );                    \
    } else {            \
        Rop[ i ]->Rip = U_PTR( p );                    \
    }

//
// casting macros
//
#define C_PTR( x )   ( ( PVOID    ) ( x ) )
#define U_PTR( x )   ( ( ULONG_PTR ) ( x ) )
#define U_PTR32( x ) ( ( ULONG    ) ( x ) )
#define U_PTR64( x ) ( ( ULONG64  ) ( x ) )
#define A_PTR( x )   ( ( PCHAR    ) ( x ) )
#define B_PTR( x )   ( ( PBYTE    ) ( x ) )
#define W_PTR( x )   ( ( PWCHAR   ) ( x ) )

//
// dereference memory macros
//
#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )

//
// memory related macros
//
#define MmCopy __builtin_memcpy
#define MmSet  __stosb
#define MmZero RtlSecureZeroMemory

#ifdef FW_DEBUG
#if FW_DEBUG == 1
#define PRINTF( ... )  Ctx->Win32.printf( __VA_ARGS__ );
#else
#define PRINTF( ... )
#endif
#endif
#pragma endregion

#pragma region [struct]

typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
} USTRING, *PUSTRING;

//
// internal ctx struct
//
typedef struct _FLOWER_CTX {
    //
    // functions
    //
    struct {
        //
        // printf
        //
#if FW_DEBUG == 1
        D_API( printf )
#endif
        //
        // ntdll
        //
        PVOID RtlMoveMemory;
        PVOID RtlZeroMemory;
        PVOID RtlUserThreadStart;
        D_API( RtlCaptureContext )
        D_API( RtlExitUserThread )

        D_API( NtFreeVirtualMemory )
        D_API( NtSignalAndWaitForSingleObject )
        D_API( NtAllocateVirtualMemory )
        D_API( NtWaitForSingleObject )
        D_API( NtDuplicateObject )
        D_API( NtCreateEvent )
        D_API( NtSetEvent )
        D_API( NtContinue )
        D_API( NtClose )
        D_API( NtSetContextThread )
        D_API( NtGetContextThread )

        //
        // kernel32
        //
        D_API( LoadLibraryW )
        D_API( LocalAlloc )
        D_API( LocalFree )
        D_API( VirtualAlloc )
        D_API( VirtualFree )
        D_API( VirtualProtect )
        D_API( WaitForSingleObjectEx )

        //
        // foliage
        //
        D_API( NtQueueApcThread )
        D_API( NtCreateThreadEx )
        D_API( NtTerminateThread )
        D_API( NtAlertResumeThread )
        D_API( NtTestAlert )
        D_API( ConvertThreadToFiberEx )
        D_API( ConvertFiberToThread )
        D_API( CreateFiberEx )
        D_API( SwitchToFiber )
        D_API( DeleteFiber )

        //
        // ekko
        //
        D_API( RtlCreateTimer )
        D_API( RtlCreateTimerQueue )
        D_API( RtlDeleteTimerQueue )


        //
        // zilean
        //
        D_API( RtlRegisterWait )

        //
        // crypt
        //
        NTSTATUS ( WINAPI* SystemFunction032 ) ( PUSTRING, PUSTRING );
    } Win32;

    //
    // modules
    //
    struct {
        PVOID Ntdll;
        PVOID Advapi32;
        PVOID Kernel32;
        PVOID Msvcrt;
    } Mods;

    struct {
        HANDLE Start;
        HANDLE Wait;
        HANDLE Delay;
        HANDLE Timer;
    } Evnts;

    //
    // behavior
    //
    ULONG Config;       // 32 bits => 32 flags, we're chilling

    //
    // flower ctx (mem info and whatnot)
    //
    PVOID   ShcBase;
    SIZE_T  ShcLength;
    PVOID   NxtBuf;     // needed for the main function to know where to rebase

} FLOWER_CTX, *PFLOWER_CTX;

//
// FwRopStart wrapper struct
// idk what type safety is
//
typedef struct _FLOWER_ROPSTART {
    //
    // NtSignalAndWaitForSingleObject + args
    //
    PVOID Func;
    PVOID Signal;
    PVOID Wait;
    PVOID Alertable;
    PVOID TimeOut;

    //
    // retaddr patching
    //
    PVOID ImgBase;
    PVOID NewBase;

} FLOWER_ROPSTART_PRM, *PFLOWER_ROPSTART_PRM;

//
// using a struct because it's easier to handle for the
// obf function
//
typedef struct _FLOWER_ROPCHAIN_PRM {
    //
    // stack masking specifics
    //
    struct {
        HANDLE Thd;
        CONTEXT SpfCtx;
        CONTEXT OgCtx;
        UCHAR EmptyStk[ 256 ];
    } Spoof;

    //
    // sleep encryption
    //
    struct {
        USTRING Key;
        USTRING Img;
    } Crypt;

    PCONTEXT RopInit;
    PVOID Gadget;

} FLOWER_ROPCHAIN_PRM, *PFLOWER_ROPCHAIN_PRM;


#pragma endregion

#pragma region [proto]
//
// core functions
//
FUNC NTSTATUS Flower( _In_ ULONG Delay, _In_ ULONG Flags );
FUNC NTSTATUS FlowerCtx( _Out_ PFLOWER_CTX Ctx, _In_ ULONG Flags );

//
// sleep obf
//
FUNC NTSTATUS FwFoliageObf( _In_ ULONG Delay, _In_ PFLOWER_CTX );
FUNC BOOL FwTimerObf( _In_ ULONG Delay, _In_ PFLOWER_CTX Ctx );

//
// rop
//
FUNC NTSTATUS FwRopChain(
        _In_  PFLOWER_CTX   Ctx,
        _In_  ULONG         Delay,
        _In_  PFLOWER_ROPCHAIN_PRM Prm,
        _In_  ULONG         Flags,
        _Out_ PCONTEXT*     Rop,
        _Out_ PSHORT       RopLen
);

FUNC NTSTATUS FwpRopAlloc(
        _In_  PFLOWER_CTX Ctx,
        _Out_ PCONTEXT*   Rop
);

FUNC NTSTATUS FwRopChainPrm(
    _In_ PFLOWER_CTX Ctx,
    _Out_ PFLOWER_ROPCHAIN_PRM Prm,
    _In_ PCONTEXT RopInit
);

//
// utils
//
FUNC ULONG FwHash( _In_ PVOID Buffer, _In_opt_ ULONG Length );
FUNC INT MemCompare( PVOID s1, PVOID s2, INT len );
FUNC PIMAGE_NT_HEADERS FwImgHeader( _In_ PVOID Image );
FUNC PVOID FwModuleHandle( _In_ ULONG Hash );
FUNC PVOID FwLdrFunction( _In_ PVOID Image, _In_ ULONG Hash );
FUNC VOID FwSharedSleep( _In_ ULONG64 Delay );
FUNC PVOID FwpMemPrepare( _In_ PFLOWER_CTX Ctx, _In_ ULONG Size );
FUNC NTSTATUS FwpRopStackFixup( _In_ PFLOWER_CTX Ctx, _In_ PCONTEXT* Rop, _In_ SHORT Count, _In_ ULONG Flags );
FUNC VOID FwEventSet( _In_ HANDLE Event );

FUNC NTSTATUS FwpRopstartPrm(
        _In_ PFLOWER_CTX Ctx,
        _In_ PFLOWER_ROPSTART_PRM Prm,
        _In_ HANDLE Event,
        _In_ HANDLE Wait,
        _In_ PVOID OldBase,
        _In_ PVOID NxtBase
);

FUNC PVOID FwGetGadget(
        _In_ PBYTE Pattern,
        _In_ SIZE_T PatternSize
);

//
// asm
//
EXTERN_C VOID FwPatchRetAddr( PVOID ImgBase, PVOID NewBase );
EXTERN_C VOID FwRopStart( FLOWER_ROPSTART_PRM Prm );

//
// markers
//
EXTERN_C PCHAR FwFuncMarker;


#pragma endregion

#pragma region [flag]

//
// main flags
//
#define FLOWER_EKKO_OBF         1 << 1
#define FLOWER_ZILEAN_OBF       1 << 2
#define FLOWER_FOLIAGE_OBF      1 << 3

//
// stackspoof
//
#define FLOWER_STACKSPOOF       1 << 4

//
// gadget flags
//
#define FLOWER_GADGET_RAX       1 << 10
#define FLOWER_GADGET_RBX       1 << 11


//
// zero flags
//
#define FLOWER_ZERO_PROTECT     1 << 20
#define FLOWER_ZERO_REALLOC     1 << 21

//
// misc
//
#define FLOWER_RWX              1 << 30


#pragma endregion

#pragma region [hash]

#define H_MODULE_NTDLL                         0x145370bb
#define H_MODULE_KERNEL32                      0x29cdd463

#define H_FUNC_LDRGETPROCEDUREADDRESS          0xeda11184
#define H_FUNC_LOADLIBRARYW                    0xd76ccd99
#define H_FUNC_LOCALALLOC                      0x4df81bbd
#define H_FUNC_LOCALFREE                       0xbbf7c456
#define H_FUNC_VIRTUALALLOC                    0x38e87001
#define H_FUNC_VIRTUALPROTECT                  0x62c5c373
#define H_FUNC_WAITFORSINGLEOBJECTEX           0xd4445251
#define H_FUNC_SYSTEMFUNCTION032               0xcff039fd
#define H_FUNC_RTLMOVEMEMORY                   0xbf79e97f
#define H_FUNC_RTLZEROMEMORY                   0x24aac1a4
#define H_FUNC_RTLALLOCATEHEAP                 0x1aff0438
#define H_FUNC_RTLFREEHEAP                     0x9d9b8ab5
#define H_FUNC_RTLEXITUSERTHREAD               0xcc77997e
#define H_FUNC_RTLCAPTURECONTEXT               0xa5201000
#define H_FUNC_NTCREATEEVENT                   0x5d9c3845
#define H_FUNC_NTSETEVENT                      0x46c7d55f
#define H_FUNC_NTFREEVIRTUALMEMORY             0x8a45ba47
#define H_FUNC_NTCONTINUE                      0x3239f036
#define H_FUNC_NTCLOSE                         0x1498d8a5
#define H_FUNC_NTDUPLICATEOBJECT               0x50bbb1d7
#define H_FUNC_NTWAITFORSINGLEOBJECT           0x239fafae
#define H_FUNC_NTALLOCATEVIRTUALMEMORY         0xd58d5a18
#define H_FUNC_NTGETCONTEXTTHREAD              0x85f22d70
#define H_FUNC_NTSETCONTEXTTHREAD              0xa1e2c124
#define H_FUNC_VIRTUALFREE                     0x81178a12
#define H_FUNC_RTLCREATETIMER                  0x9452c6c2
#define H_FUNC_RTLCREATETIMERQUEUE             0x35aa5785
#define H_FUNC_RTLDELETETIMERQUEUE             0xff423c82
#define H_FUNC_RTLREGISTERWAIT                 0x2c4525c9
#define H_FUNC_NTQUEUEAPCTHREAD                0xbed494ac
#define H_FUNC_NTCREATETHREADEX                0xc00335da
#define H_FUNC_NTTERMINATETHREAD               0x5350af1e
#define H_FUNC_NTTESTALERT                     0xf586cf8f
#define H_FUNC_RTLUSERTHREADSTART              0xd5cfe98e
#define H_FUNC_NTALERTRESUMETHREAD             0xe9d3cd48
#define H_FUNC_CONVERTTHREADTOFIBEREX          0x9d25a298
#define H_FUNC_CONVERTFIBERTOTHREAD            0x366db59f
#define H_FUNC_CREATEFIBEREX                   0x497c7124
#define H_FUNC_SWITCHTOFIBER                   0xfa2c6942
#define H_FUNC_DELETEFIBER                     0x1f257c4
#define H_FUNC_NTSIGNALANDWAITFORSINGLEOBJECT  0x4f81bb17
#define H_FUNC_PRINTF                          0xb81dd0ea
#pragma endregion

#endif /// FLOWER_FLOWER_H
