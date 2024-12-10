#include <ntifs.h>

VOID VisitSSDT(PFUNCTION_MAP exportsMap, PVOID kiServiceTable, ULONG numberOfServices) {

	for (int i = 0; i < (int)numberOfServices; i++) {

		__try {
			ULONG offset = (*(PLONG)((DWORD64)kiServiceTable + 4 * i));

			if (offset != 0) {

				ULONGLONG functionAddress = (ULONGLONG)((DWORD64)kiServiceTable + ((ULONG)offset >> 4));
				PCWSTR functionName = FindFunctionName(exportsMap, (PVOID)functionAddress);

				if (functionName) {
					DbgPrint("\t\t[%i] - %ws - %p\n", i, functionName, functionAddress);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("[-] Exception\n");
		}
	}
}

