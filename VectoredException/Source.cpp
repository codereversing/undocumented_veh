#include <stdio.h>
#include <Windows.h>

#include "peb.h"
#include "native.h"

/***** These will change on startup *****/
#ifdef _M_IX86
const DWORD_PTR VectorHandlerListBase = 0x771EFCE4;
#elif defined _M_AMD64
const DWORD_PTR VectorHandlerListBase = 0x0000000076F56350;
#else
#error "Unsupported architecture"
#endif


using pNtQueryInformationProcess = NTSTATUS (WINAPI *)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
                                                      PVOID ProcessInformation, ULONG ProcessInformationLength,
                                                      PULONG ReturnLength);
pNtQueryInformationProcess NtQueryInformationProcess = nullptr;

LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    printf("Test 1!\n");

    return EXCEPTION_CONTINUE_SEARCH;
}

LONG CALLBACK VectoredHandler2(PEXCEPTION_POINTERS ExceptionInfo)
{
    printf("Test 2!\n");

    return EXCEPTION_CONTINUE_SEARCH;
}

LONG CALLBACK VectoredHandler3(PEXCEPTION_POINTERS ExceptionInfo)
{
    printf("Test 3!\n");

    return EXCEPTION_CONTINUE_SEARCH;
}

typedef struct _LdrpVectorHandlerEntry
{
    _LdrpVectorHandlerEntry *pNext;
    _LdrpVectorHandlerEntry *pPrev;
    DWORD dwAlwaysOne;
    PVECTORED_EXCEPTION_HANDLER pVectoredHandler;
} VECTORED_HANDLER_ENTRY, *PVECTORED_HANDLER_ENTRY; 

typedef struct _LdrpVectorHandlerList
{
    SRWLOCK srwLock;
    VECTORED_HANDLER_ENTRY *pFirstHandler;
    VECTORED_HANDLER_ENTRY *pLastHandler;

} VECTORED_HANDLER_LIST, *PVECTORED_HANDLER_LIST; 

//Not the way its done in implementation, but wrote it as platform independent for easy
//x86 and x64 interoperability
PPEB GetPEB()
{
    PPEB pPeb = nullptr;

    if(NtQueryInformationProcess == nullptr)
    {
        fprintf(stderr, "Could not find NtQueryInformationProcess function. Error = %X.\n",
            GetLastError());
        abort();
    }
    
    PROCESS_BASIC_INFORMATION procBasicInfo = { 0 };
    NTSTATUS ntSuccess = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &procBasicInfo,
        sizeof(PROCESS_BASIC_INFORMATION), nullptr);
    pPeb = procBasicInfo.PebBaseAddress;

    return pPeb;
}

//Used non-native APIs here for convenience.
PVOID RtlAddVectoredExceptionHandler(ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler, int Unknown)
{
    PPEB pPeb = GetPEB();
    
    VECTORED_HANDLER_ENTRY *pVecNewEntry =
        (VECTORED_HANDLER_ENTRY *)HeapAlloc((HANDLE)pPeb->ProcessHeap, 0, sizeof(VECTORED_HANDLER_ENTRY));
    if(pVecNewEntry == nullptr)
    {
        return nullptr;
    }
    pVecNewEntry->dwAlwaysOne = 1;

    PVOID pEncodedHandler = EncodePointer(VectoredHandler);
    VECTORED_HANDLER_LIST *pVecHandlerBase = (VECTORED_HANDLER_LIST *)(VectorHandlerListBase);

    AcquireSRWLockExclusive(&pVecHandlerBase->srwLock);

    pVecNewEntry->pVectoredHandler = (PVECTORED_EXCEPTION_HANDLER)pEncodedHandler;

    //If the list is empty then set the CrossProcessFlags fields
    if(pVecHandlerBase->pFirstHandler == (VECTORED_HANDLER_ENTRY *)&pVecHandlerBase->pFirstHandler)
    {
        InterlockedBitTestAndSet((LONG *)&pPeb->CrossProcessFlags, 2);
    }

    if(FirstHandler)
    {
        //Insert new node at the head of the VEH list
        pVecNewEntry->pNext = pVecHandlerBase->pFirstHandler;
        pVecNewEntry->pPrev = (VECTORED_HANDLER_ENTRY *)&pVecHandlerBase->pFirstHandler;
        pVecHandlerBase->pFirstHandler->pPrev = pVecNewEntry;
        pVecHandlerBase->pFirstHandler = pVecNewEntry;
    }
    else
    {
        //Insert new node at the end of the VEH list
        pVecNewEntry->pNext = (VECTORED_HANDLER_ENTRY *)&pVecHandlerBase->pFirstHandler;
        pVecNewEntry->pPrev = pVecHandlerBase->pLastHandler;
        pVecHandlerBase->pLastHandler->pNext = pVecNewEntry;
        pVecHandlerBase->pLastHandler = pVecNewEntry;
    }

    ReleaseSRWLockExclusive(&pVecHandlerBase->srwLock);

    return (PVOID)pVecNewEntry;
}

int main(int argc, char *argv[])
{
    NtQueryInformationProcess = (pNtQueryInformationProcess)
        GetProcAddress(GetModuleHandle(L"ntdll.dll"),"NtQueryInformationProcess");
    
    //Handlers will be called in 2, 3, 1 order.
    auto i = RtlAddVectoredExceptionHandler(0x1, VectoredHandler, 0);
    PVOID k = AddVectoredExceptionHandler(0x0, VectoredHandler3);
    auto j = RtlAddVectoredExceptionHandler(0x1, VectoredHandler2, 0);

    RaiseException(0x123, 0, 0, 0);
    
    return 0;
}
