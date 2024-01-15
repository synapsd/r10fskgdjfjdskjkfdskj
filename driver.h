#include "check.h"
#include "Func.h"
#include "../sdk/xor.h"

uintptr_t kschltygf;

#define knzredio CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0658A, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define cdeknzsc CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0334E, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


typedef struct _knzrdwrt {
	INT32 Knzproc_iidd;
	ULONGLONG knzadrres;
	ULONGLONG knzbffr;
	ULONGLONG knzsize;
	BOOLEAN knzwrttt;
} rw, * prw;


typedef struct _ba {
	INT32 Knzproc_iidd;
	ULONGLONG* knzadrres;
} ba, * pba;


typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBigPoolInformation = 0x42
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(
	IN _SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID                   SystemInformation,
	IN ULONG                    SystemInformationLength,
	OUT PULONG                  ReturnLength
	);

__forceinline auto query_bigpools() -> PSYSTEM_BIGPOOL_INFORMATION
{
	static const pNtQuerySystemInformation NtQuerySystemInformation =
		(pNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

	DWORD length = 0;
	DWORD size = 0;
	LPVOID heap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0);
	heap = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, heap, 0xFF);
	NTSTATUS ntLastStatus = NtQuerySystemInformation(SystemBigPoolInformation, heap, 0x30, &length);
	heap = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, heap, length + 0x1F);
	size = length;
	ntLastStatus = NtQuerySystemInformation(SystemBigPoolInformation, heap, size, &length);

	return reinterpret_cast<PSYSTEM_BIGPOOL_INFORMATION>(heap);
}
__forceinline auto get_guarded() -> uintptr_t
{
	auto pool_information = query_bigpools();
	uintptr_t guarded = 0;

	if (pool_information)
	{
		auto count = pool_information->Count;
		for (auto i = 0ul; i < count; i++)
		{
			SYSTEM_BIGPOOL_ENTRY* allocation_entry = &pool_information->AllocatedInfo[i];
			const auto virtual_address = (PVOID)((uintptr_t)allocation_entry->VirtualAddress & ~1ull);
			if (allocation_entry->NonPaged && allocation_entry->SizeInBytes == 0x200000)
				if (guarded == 0 && allocation_entry->TagUlong == 'TnoC')
					guarded = reinterpret_cast<uintptr_t>(virtual_address);
		}
	}

	return guarded;
}

namespace kcvh {
	HANDLE knzdruv_hnd;
	INT32 Knzproc_iidd;

	bool knzfnddruv() {
		knzdruv_hnd = CreateFileW(_(L"\\\\.\\\{e5806-b0334-a0981}"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (!knzdruv_hnd || (knzdruv_hnd == INVALID_HANDLE_VALUE))
			return false;

		return true;
	}

	INT32 kcprfnd(LPCTSTR process_name) {
		PROCESSENTRY32 pt;
		HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pt.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hsnap, &pt)) {
			do {
				if (!lstrcmpi(pt.szExeFile, process_name)) {
					CloseHandle(hsnap);
					Knzproc_iidd = pt.th32ProcessID;
					return pt.th32ProcessID;
				}
			} while (Process32Next(hsnap, &pt));
		}
		CloseHandle(hsnap);
		return Knzproc_iidd;
	}

	uintptr_t kscvhimdh() {
		uintptr_t image_address = { NULL };
		_ba arguments = { NULL };

		arguments.Knzproc_iidd = Knzproc_iidd;
		arguments.knzadrres = (ULONGLONG*)&image_address;

		DeviceIoControl(knzdruv_hnd, cdeknzsc, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);

		return image_address;
	}

	void knzwrttt_physical(PVOID address, PVOID buffer, DWORD size) {
		_knzrdwrt arguments = { 0 };

		arguments.knzadrres = (ULONGLONG)address;
		arguments.knzbffr = (ULONGLONG)buffer;
		arguments.knzsize = size;
		arguments.Knzproc_iidd = Knzproc_iidd;
		arguments.knzwrttt = TRUE;

		DeviceIoControl(knzdruv_hnd, knzredio, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

	void kanzrrdd_physical(PVOID address, PVOID buffer, DWORD size) {
		_knzrdwrt arguments = { 0 };

		arguments.knzadrres = (ULONGLONG)address;
		arguments.knzbffr = (ULONGLONG)buffer;
		arguments.knzsize = size;
		arguments.Knzproc_iidd = Knzproc_iidd;
		arguments.knzwrttt = FALSE;

		DeviceIoControl(knzdruv_hnd, knzredio, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

}

template <typename T>
T kanzrrdd22(uint64_t address) {
	T buffer{ };
	kcvh::kanzrrdd_physical((PVOID)address, &buffer, sizeof(T));
	if (check::is_guarded(buffer))
	{
		buffer = check::validate_pointer(buffer);
	}

	return buffer;
}

template <typename T>
T kanzrrdd(uint64_t address) {
	T buffer{ };
	kcvh::kanzrrdd_physical((PVOID)address, &buffer, sizeof(T));

	return buffer;
}

template <typename T>
T kanzwrttt(uint64_t address, T buffer) {

	kcvh::knzwrttt_physical((PVOID)address, &buffer, sizeof(T));
	return buffer;
}
