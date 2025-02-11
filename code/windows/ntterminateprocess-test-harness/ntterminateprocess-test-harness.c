// NtTerminateProcess Test Harness
//
// Isolate for the variable of how NtTerminateProcess affects module destructors (e.g. DLL_PROCESS_DETACH)
// We make the same NtTerminateProcess system call Windows makes every process exit before running module destructors
//
// Note: We don't acquire the load/loader, PEB, and process heap locks like Windows does before NtTerminateProcess then releasing the latter two locks immediately after.
// However, for our debugging purposes, I just manually whether those locks are held in WinDbg to ensure realistic results (it's unlikely that those exact locks are held at the exact time of NtTerminateProcess, but anything is possible with concurrency)
//
// Note: We use ShellExecute in some of these tests; however, much of the USER API in Windows is guilty of the same correctness issues we demo here (ShellExecute is just easy to test with)
// https://learn.microsoft.com/en-us/windows/win32/api/winuser/
//
// To compile:
// Link to NTDLL by navigating from `Project > Properties`, go to `Linker > Input` then append to `Additional Dependencies`: `ntdll.lib`. Configure this for `All Configurations` and `All Platforms`.

#include <windows.h>
#include <stdio.h>

// Prototype from ReactOS
EXTERN_C NTSTATUS NTAPI NtTerminateProcess(IN HANDLE ProcessHandle OPTIONAL, IN NTSTATUS ExitStatus);

void PrintLastError(void)
{
    DWORD dwMessageId = GetLastError();
    if (dwMessageId == 0)
        return;

    LPWSTR lpBuffer = NULL;

    size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, dwMessageId, 0, (LPWSTR)&lpBuffer, 0, NULL);

    wprintf(L"Error %d: %ls", dwMessageId, lpBuffer);

    LocalFree(lpBuffer);
}

void simulateProcessExit() {
    // WinDbg Commands (copy & paste):
    /*
!handle poi(ntdll!LdrpLoadCompleteEvent) 8
!critsec ntdll!LdrpLoaderLock
!critsec ntdll!FastPebLock
!critsec @@C++(&((ntdll!_HEAP*)(@$peb->ProcessHeap))->LockVariable->Lock.CriticalSection)
    */
    // The last command only applies to the default NT Heap since the Segment Heap uses many independent (SRW) locks to improve concurrency

    __debugbreak();
    NtTerminateProcess(0, 0);
}

void test1Thread(LPVOID lpParam) {
    // This will never happen
    puts("Reached test 1 thread!");
    __debugbreak();
}

void test1() {
    simulateProcessExit();

    // Attempt creating a thread
    DWORD dwThread;
    HANDLE myThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)test1Thread, NULL, 0, &dwThread);
    PrintLastError();

    // Output:
    // Error 5: Access is denied.
    //
    // Following NtTerminateProcess, the NT kernel blocks our thread creation attempt from a module destructor
}

void test2() {
    simulateProcessExit();

    // Fail horribly
    ShellExecute(NULL, L"open", L"calc.exe", NULL, NULL, SW_SHOW);
    __debugbreak();

    // Output:
    // *Deadlock occurs*
    // 0:000> k
    // # Child-SP          RetAddr               Call Site
    // 00 000000dc`cd54c5d8 00007ff9`da11360f     ntdll!NtAlpcSendWaitReceivePort+0x14
    // 01 000000dc`cd54c5e0 00007ff9`da12a4a7     RPCRT4!LRPC_BASE_CCALL::SendReceive+0x12f
    // 02 000000dc`cd54c6b0 00007ff9`da0d1fc0     RPCRT4!NdrpSendReceive+0x97
    // 03 000000dc`cd54c6e0 00007ff9`da0d19df     RPCRT4!NdrpClientCall2+0x5d0
    // 04 000000dc`cd54cd00 00007ff9`dac68e51     RPCRT4!NdrClientCall2+0x1f
    // 05 (Inline Function) --------`--------     combase!ServerAllocateOXIDAndOIDs+0x73 [onecore\com\combase\idl\internal\daytona\objfre\amd64\lclor_c.c @ 313]
    // 06 000000dc`cd54cd30 00007ff9`dac68ccd     combase!CRpcResolver::ServerRegisterOXID+0xd5 [onecore\com\combase\dcomrem\resolver.cxx @ 1056]
    // 07 000000dc`cd54cdf0 00007ff9`dac69521     combase!OXIDEntry::RegisterOXIDAndOIDs+0x71 [onecore\com\combase\dcomrem\ipidtbl.cxx @ 1642]
    // 08 (Inline Function) --------`--------     combase!OXIDEntry::AllocOIDs+0xc2 [onecore\com\combase\dcomrem\ipidtbl.cxx @ 1696]
    // 09 000000dc`cd54cf00 00007ff9`dac1eb33     combase!CComApartment::CallTheResolver+0x14d [onecore\com\combase\dcomrem\aprtmnt.cxx @ 693]
    // 0a 000000dc`cd54d0b0 00007ff9`dac177ff     combase!CComApartment::InitRemoting+0x25b [onecore\com\combase\dcomrem\aprtmnt.cxx @ 991]
    // 0b (Inline Function) --------`--------     combase!CComApartment::StartServer+0x52 [onecore\com\combase\dcomrem\aprtmnt.cxx @ 1214]
    // 0c 000000dc`cd54d120 00007ff9`dac23da1     combase!InitChannelIfNecessary+0xbf [onecore\com\combase\dcomrem\channelb.cxx @ 1028]
    // 0d 000000dc`cd54d150 00007ff9`dac23d34     combase!CGIPTable::RegisterInterfaceInGlobalHlp+0x61 [onecore\com\combase\dcomrem\giptbl.cxx @ 815]
    // 0e 000000dc`cd54d200 00007ff9`d6be5033     combase!CGIPTable::RegisterInterfaceInGlobal+0x14 [onecore\com\combase\dcomrem\giptbl.cxx @ 776]
    // 0f 000000dc`cd54d240 00007ff9`d6bdf4db     windows_storage!CFreeThreadedItemContainer::Initialize+0xf3
    // 10 000000dc`cd54d2b0 00007ff9`d6bed61a     windows_storage!CFSFolder::_BindToChild+0x35b
    // 11 000000dc`cd54de70 00007ff9`d6becaee     windows_storage!CFSFolder::_Bind+0x9da
    // 12 000000dc`cd54e290 00007ff9`d6bec318     windows_storage!CFSFolder::BindToObject+0x44e
    // 13 000000dc`cd54e620 00007ff9`d6bf2ffb     windows_storage!CShellItem::BindToHandler+0x548
    // 14 000000dc`cd54e980 00007ff9`d6c2e3df     windows_storage!CShellItem::_GetPropertyStoreWorker+0x9b
    // 15 000000dc`cd54eec0 00007ff9`d6bb36d8     windows_storage!CShellItem::GetPropertyStore+0xcf
    // 16 000000dc`cd54f190 00007ff9`d6bb32bb     windows_storage!wil::PropertyStoreHelperBase<IPropertyStore>::InitFromItem+0x84
    // 17 000000dc`cd54f1f0 00007ff9`d6b93eaa     windows_storage!IsItemUnderStorageProvider+0x4f
    // 18 000000dc`cd54f280 00007ff9`d6b93bd5     windows_storage!CBindAndInvokeStaticVerb::EnsureAssociationIDForTelemetryAndAlert+0x216
    // 19 000000dc`cd54f330 00007ff9`d6b92881     windows_storage!CBindAndInvokeStaticVerb::ConfirmUserChoiceIfNewHandlersAvailable+0x49
    // 1a 000000dc`cd54f390 00007ff9`d941543d     windows_storage!CBindAndInvokeStaticVerb::Execute+0x141
    // 1b 000000dc`cd54f6b0 00007ff9`d9413fe1     SHELL32!CShellExecute::_ExecuteAssoc+0x10d
    // 1c 000000dc`cd54f720 00007ff9`d941120c     SHELL32!CShellExecute::_DoExecute+0xd9
    // 1d 000000dc`cd54f790 00007ff9`d9411d7b     SHELL32!CShellExecute::ExecuteNormal+0x1fc
    // 1e 000000dc`cd54f970 00007ff9`d94115be     SHELL32!ShellExecuteNormal+0xa3
    // 1f 000000dc`cd54f9d0 00007ff9`d94cb571     SHELL32!ShellExecuteExW+0xde
    // 20 000000dc`cd54fb70 00007ff6`6a5d1049     SHELL32!ShellExecuteW+0x81
    // 21 000000dc`cd54fc30 00007ff6`6a5d1244     ConsoleApplication2!main+0x39 [C:\Users\user\source\repos\ConsoleApplication2\ConsoleApplication2\ConsoleApplication2.cpp @ 212]
    // 22 (Inline Function) --------`--------     ConsoleApplication2!invoke_main+0x22 [d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 78]
    // 23 000000dc`cd54fc70 00007ff9`daab7344     ConsoleApplication2!__scrt_common_main_seh+0x10c [d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 288]
    // 24 000000dc`cd54fcb0 00007ff9`db3a26b1     KERNEL32!BaseThreadInitThunk+0x14
    // 25 000000dc`cd54fce0 00000000`00000000     ntdll!RtlUserThreadStart+0x21
    //
    // The COM server deadlock we've seen before appears. However, this one's a bit different because it shows that, at DLL_PROCESS_DETACH, COM server creation is also blocked following NtTerminateProcess.
}

void test3() {
    // Successful first ShellExecute
    ShellExecute(NULL, L"open", L"calc.exe", NULL, NULL, SW_SHOW);
    __debugbreak();

    // Even if I put a 10 second delay here before the process exit simulation, we will get this deadlock
    // This appears to be because, while I cannot actively see any work being done on the thread anymore, the SHCORE message loop keeps a Win32 event object waiting even while it does nothing but listen for messages. This is supposedly to ensure that no other thread can read from the message loop at the same time.
    Sleep(10000);

    // Prepare to fail!
    simulateProcessExit();

    // Fail horribly in a random way
    ShellExecute(NULL, L"open", L"calc.exe", NULL, NULL, SW_SHOW);
    __debugbreak();

    // Output:
    // The first ShellExecute happens correctly then on the second ShellExecute...
    // *Deadlock occurs*
    // 0:000> k
    //  # Child-SP          RetAddr               Call Site
    // 00 0000005f`6ad1e918 00007ff9`d8d630ce     ntdll!NtWaitForSingleObject+0x14
    // 01 0000005f`6ad1e920 00007ff9`d9cb5ee4     KERNELBASE!WaitForSingleObjectEx+0x8e
    // 02 0000005f`6ad1e9c0 00007ff9`d9cb5b58     SHCORE!WorkThreadManager::s_QueuePoolTask+0x164
    // 03 0000005f`6ad1ea60 00007ff9`d6caa038     SHCORE!SHTaskPoolQueueTask+0xe8
    // 04 0000005f`6ad1ead0 00007ff9`d6b95342     windows_storage!Windows::Internal::ComTaskPool::RunSynchronousTaskOnMTA<<lambda_88ebc11be37ccc60a9fb0a9617d91f45> >+0xa4
    // 05 0000005f`6ad1eb30 00007ff9`d6b91038     windows_storage!CBindAndInvokeStaticVerb::StoreHintsAndReportUserAssistInfo+0x322
    // 06 0000005f`6ad1ec00 00007ff9`d6b922e7     windows_storage!CInvokeCreateProcessVerb::NotifyBeforeCreateProcess+0x88
    // 07 0000005f`6ad1ec60 00007ff9`d6bbf3bc     windows_storage!CInvokeCreateProcessVerb::_PrepareAndCallCreateProcess+0x29b
    // 08 0000005f`6ad1ece0 00007ff9`d6bbf1e3     windows_storage!CInvokeCreateProcessVerb::_TryCreateProcess+0x3c
    // 09 0000005f`6ad1ed10 00007ff9`d6bbf84d     windows_storage!CInvokeCreateProcessVerb::Launch+0xef
    // 0a 0000005f`6ad1edb0 00007ff9`d6cab06a     windows_storage!CInvokeCreateProcessVerb::Execute+0x5d
    // 0b 0000005f`6ad1edf0 00007ff9`d6bbf9ff     windows_storage!CBindAndInvokeStaticVerb::InitAndCallExecute+0x22a
    // 0c 0000005f`6ad1ee70 00007ff9`d6b92927     windows_storage!CBindAndInvokeStaticVerb::TryCreateProcessDdeHandler+0x63
    // 0d 0000005f`6ad1eef0 00007ff9`d941543d     windows_storage!CBindAndInvokeStaticVerb::Execute+0x1e7
    // 0e 0000005f`6ad1f210 00007ff9`d9413fe1     SHELL32!CShellExecute::_ExecuteAssoc+0x10d
    // 0f 0000005f`6ad1f280 00007ff9`d941120c     SHELL32!CShellExecute::_DoExecute+0xd9
    // 10 0000005f`6ad1f2f0 00007ff9`d9411d7b     SHELL32!CShellExecute::ExecuteNormal+0x1fc
    // 11 0000005f`6ad1f4d0 00007ff9`d94115be     SHELL32!ShellExecuteNormal+0xa3
    // 12 0000005f`6ad1f530 00007ff9`d94cb571     SHELL32!ShellExecuteExW+0xde
    // 13 0000005f`6ad1f6d0 00007ff7`661d1074     SHELL32!ShellExecuteW+0x81
    // 14 0000005f`6ad1f790 00007ff7`661d126c     ConsoleApplication2!main+0x64 [C:\Users\user\source\repos\ConsoleApplication2\ConsoleApplication2\ConsoleApplication2.cpp @ 196]
    // 15 (Inline Function) --------`--------     ConsoleApplication2!invoke_main+0x22 [d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 78]
    // 16 0000005f`6ad1f7d0 00007ff9`daab7344     ConsoleApplication2!__scrt_common_main_seh+0x10c [d:\a01\_work\20\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 288]
    // 17 0000005f`6ad1f810 00007ff9`db3a26b1     KERNEL32!BaseThreadInitThunk+0x14
    // 18 0000005f`6ad1f840 00000000`00000000     ntdll!RtlUserThreadStart+0x21
    // We hang indefinitely on a waiting Win32 event object:
    // 0:000> r rcx
    // rcx=0000000000000274
    // 0:000> !handle 274 ff Event
    // Handle 274
    //  Type         	Event
    // Attributes   	0
    //  GrantedAccess	0x1f0003:
    //         Delete,ReadControl,WriteDac,WriteOwner,Synch
    //         QueryState,ModifyState
    //  HandleCount  	2
    //  PointerCount 	65533
    //  Name         	<none>
    //  Object Specific Information
    //    Event Type Auto Reset
    //    Event is Waiting
    //
    // Running ShellExecute twice (one before NtTerminateProcess and one after NtTerminateProcess) fails because the Windows API keeps working on other threads even after the first ShellExecute returns (the specific COM server is already in the process now or CSRSS initialization is done, I'm not sure which, so we don't deadlock in the place we would when just running a single ShellExecute from a module destructor)
    // Because the Windows API doesn't join back to the main thread and keeps working in the background after ShellExecute, NtTerminateProcess is fatal because it kills threads holding synchronization objects thereby abandoning them and leaving anyone else who unknowingly later uses the abandoned syncronization objects later to deadlock, crash, etc.
    // This is incorrect behavior on part of the Windows API because threads must join back to the main thread or stop working within the process lifetime
    // The Windows API shouldn't create background threads in your process that work past the use of the Windows API function or module destructors run at process exit should include code that gracefully signals to any alive threads and join them back
    // This incorrect behavior also occurs with many other Windows USER API functions (ShellExecute is just an easy example)
    // The NtTerminateThread documentation specifically warns against killing threads in a running state and yet here Microsoft is doing exactly that
    //
    // Note that some ShellExecute internals may implement a workaround by checking PEB_LDR_DATA.ShutdownInProgress, but that would still only be an ad-hoc bandage patch for this specifc occurrence of a symptom of the root issue
}

void test4() {
    // Successful first ShellExecute
    ShellExecute(NULL, L"open", L"calc.exe", NULL, NULL, SW_SHOW);

    Sleep(10000);

    simulateProcessExit();

    // Fail horribly in a random way
    ShellExecute(NULL, L"open", L"calc.exe", NULL, NULL, SW_SHOW);
    __debugbreak();

    // Output:
    // The first ShellExecute happens correctly then on the second ShellExecute...
    // *Deadlock occurs*
    // It's the same deadlocked call stack we see in test 3
    //
    // This appears to be because, while after the 10 second wait I cannot actively see any work being done on the threads anymore, the SHCORE message loop keeps a Win32 event object waiting even while it does nothing so no other thread can read from the message loop at the same time (at least, that's my best guess)
    // SHCore thread call stack before NtTerminateProcess (this is not a deadlock):
    //0:000> k
    //  # Child-SP          RetAddr               Call Site
    // 00 00000054`73bff648 00007ff9`da800dee     win32u!NtUserMsgWaitForMultipleObjectsEx+0x14
    // 01 00000054`73bff650 00007ff9`d9cb76f1     USER32!RealMsgWaitForMultipleObjectsEx+0x1e
    // 02 00000054`73bff690 00007ff9`d9cb6be0     SHCORE!WorkThreadManager::CThread::ThreadProc+0xae1
    // 03 00000054`73bff920 00007ff9`d9cb53e1     SHCORE!WorkThreadManager::CThread::s_ExecuteThreadProc+0x18
    // 04 00000054`73bff950 00007ff9`daab7344     SHCORE!<lambda_9844335fc14345151eefcc3593dd6895>::<lambda_invoker_cdecl>+0x11
    // 05 00000054`73bff980 00007ff9`db3a26b1     KERNEL32!BaseThreadInitThunk+0x14
    // 06 00000054`73bff9b0 00000000`00000000     ntdll!RtlUserThreadStart+0x21
    //
    // Members of the Windows USER API following this practice makes NtTerminateProcess especially deadly
}

void test5() {
	// Use calc variant, not calc.exe (Windows is weird about file extensions)
	// This one spawns the SHCORE!_WrapperThreadProc background thread
	ShellExecute(NULL, L"open", L"calc", NULL, NULL, SW_SHOW);
	__debugbreak();
    // Optional: For analyzing the actual running thread state (including the reason for waiting) in Process Explorer (since breaking in WinDbg will suspend all threads thereby concealing this information)
    //Sleep(INFINITE);
}

int main() {
    test1();
}
