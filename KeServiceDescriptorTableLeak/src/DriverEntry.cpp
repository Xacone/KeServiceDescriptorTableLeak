#pragma warning(disable:4201)

#include "Pe.h"
#include "Utils.h"
#include "Ssdt.h"

extern "C" ULONGLONG __readmsr(ULONG);
extern "C" NTKERNELAPI PLIST_ENTRY PsLoadedModuleList;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
    PULONG ServiceTableBase;
    PULONG ServiceCounterTableBase;
    ULONG NumberOfServices;
    PUCHAR ParamTableBase;
} SERVICE_DESCRIPTOR_TABLE, * PSERVICE_DESCRIPTOR_TABLE;

FUNCTION_MAP ExportsMap;

PDEVICE_OBJECT deviceObject = NULL;

ULONGLONG LeakKiSystemServiceUser() {

    QWORD KiSystemCall64Shadow = (QWORD)__readmsr(0xC0000082);
    ULONGLONG lastJmpAddr = NULL;

    do {
        __try {

            KiSystemCall64Shadow += 2;
            UINT8 jmp_byte[] = { 0xE9 };

            if (contains_bytes_bitwise(*(PULONG)KiSystemCall64Shadow, jmp_byte, 1)) {
                lastJmpAddr = KiSystemCall64Shadow;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] Exception\n");
            return NULL;
        }

    } while (*(PULONG)KiSystemCall64Shadow != 0);

    LONG kiSystemServiceUserOffset = -(*(PLONG)(lastJmpAddr + 2));
    ULONGLONG kiSystemServiceUser = (ULONGLONG)((lastJmpAddr + 2 + 4) - (LONG)kiSystemServiceUserOffset);

    return kiSystemServiceUser;
}

ULONGLONG LeakKeServiceDescriptorTable(ULONGLONG kiSystemUser) {

    for (int i = 0; i < 0x1000; i++) {

        __try {
            UINT8 sig_bytes[] = { 0x4C, 0x8D, 0x15 };

            ULONGLONG val = *(PULONGLONG)kiSystemUser;

            if (contains_signature((ULONGLONG)&val, 8, sig_bytes, sizeof(sig_bytes))) {

                ULONG kiSystemServiceRepeatOffset = (*(PLONG)(kiSystemUser + 8));

                ULONGLONG keServiceDescriptorTable = kiSystemUser + 12 + kiSystemServiceRepeatOffset;

                return keServiceDescriptorTable;
            }

            kiSystemUser += 2;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] Exception\n");
            return NULL;
        }
    }
    return NULL;
}

PVOID GetKernelBaseAddress() {

    PLIST_ENTRY listEntry = PsLoadedModuleList;

    if (!listEntry) {
        KdPrint(("PsLoadedModuleList is NULL.\n"));
        return nullptr;
    }

    auto firstEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    return firstEntry->DllBase;
}

VOID DriverUnload(PDRIVER_OBJECT driverObject) {
    UNREFERENCED_PARAMETER(driverObject);
    DbgPrint("[+] Unloading driver\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {

    UNREFERENCED_PARAMETER(registryPath);

    driverObject->DriverUnload = DriverUnload;

    NTSTATUS status = IoCreateDevice(driverObject, 0, NULL, FILE_DEVICE_NETWORK, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    InitializeFunctionMap(&ExportsMap);

    ULONGLONG KiSystemUser = LeakKiSystemServiceUser();
    DbgPrint("[+] KiSystemServiceUser: %p\n", KiSystemUser);

    ULONGLONG KeServiceDescriptorTable = LeakKeServiceDescriptorTable(KiSystemUser);
    DbgPrint("[+] KeServiceDescriptorTable: %p\n", KeServiceDescriptorTable);

    GetAndStoreKernelExports(GetKernelBaseAddress(), &ExportsMap);

    __try {

        PSERVICE_DESCRIPTOR_TABLE serviceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE)KeServiceDescriptorTable;
        DbgPrint("[+] NumberOfServices: %d\n", serviceDescriptorTable->NumberOfServices);

        VisitSSDT(
			&ExportsMap,
            serviceDescriptorTable->ServiceTableBase,
            serviceDescriptorTable->NumberOfServices
        );

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {

        DbgPrint("[-] Exception\n");
    }

    return STATUS_SUCCESS;
}