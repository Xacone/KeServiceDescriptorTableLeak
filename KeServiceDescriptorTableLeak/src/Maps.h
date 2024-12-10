#include <ntifs.h>

typedef struct _FUNCTION_MAP_ENTRY {
    PVOID FunctionAddress;
    UNICODE_STRING FunctionName;
    struct _FUNCTION_MAP_ENTRY* Next;
} FUNCTION_MAP_ENTRY, * PFUNCTION_MAP_ENTRY;

typedef struct _FUNCTION_MAP {
    PFUNCTION_MAP_ENTRY Head;
    KSPIN_LOCK Lock;
} FUNCTION_MAP, * PFUNCTION_MAP;

VOID InitializeFunctionMap(PFUNCTION_MAP FunctionMap) {
    FunctionMap->Head = NULL;
    KeInitializeSpinLock(&FunctionMap->Lock);
}

BOOLEAN AddFunctionToMap(PFUNCTION_MAP FunctionMap, PVOID Address, PCWSTR Name) {
    KIRQL oldIrql;
    PFUNCTION_MAP_ENTRY entry = (PFUNCTION_MAP_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FUNCTION_MAP_ENTRY), 'fntM');
    if (!entry) return FALSE;

    entry->FunctionAddress = Address;
    RtlInitUnicodeString(&entry->FunctionName, Name);
    entry->Next = NULL;

    KeAcquireSpinLock(&FunctionMap->Lock, &oldIrql);
    entry->Next = FunctionMap->Head;
    FunctionMap->Head = entry;
    KeReleaseSpinLock(&FunctionMap->Lock, oldIrql);

    return TRUE;
}

PCWSTR FindFunctionName(PFUNCTION_MAP FunctionMap, PVOID Address) {
    KIRQL oldIrql;
    PFUNCTION_MAP_ENTRY current;

    KeAcquireSpinLock(&FunctionMap->Lock, &oldIrql);
    current = FunctionMap->Head;
    while (current) {
        if (current->FunctionAddress == Address) {
            KeReleaseSpinLock(&FunctionMap->Lock, oldIrql);
            return current->FunctionName.Buffer;
        }
        current = current->Next;
    }
    KeReleaseSpinLock(&FunctionMap->Lock, oldIrql);
    return NULL;
}