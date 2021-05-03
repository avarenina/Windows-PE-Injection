#include "Imports.h"

typedef PVOID(NTAPI *RtlAllocateHeap_)( // HeapAlloc essentially calls this
	_In_     PVOID  HeapHandle,
	_In_opt_ ULONG  Flags,
	_In_     SIZE_T Size
	);

typedef BOOLEAN(NTAPI *RtlFreeHeap_)(
	_In_     PVOID HeapHandle,
	_In_opt_ ULONG Flags,
	_In_     PVOID HeapBase
	);
typedef LPVOID(WINAPI *HeapAlloc_)(
	_In_ HANDLE hHeap,
	_In_ DWORD  dwFlags,
	_In_ SIZE_T dwBytes
	);

typedef SIZE_T(WINAPI *HeapSize_)(
	_In_ HANDLE  hHeap,
	_In_ DWORD   dwFlags,
	_In_ LPCVOID lpMem
	);


typedef HANDLE(WINAPI *GetProcessHeap_)(void);

PPEB32 GetPEB()
{
	_asm MOV EAX, DWORD PTR FS : [30h]
}

__declspec(naked) void GetImageBase()
{
	__asm
	{
		mov EAX, GetImageBase
		and eax, 0xFFFF0000
		find:
		cmp word ptr[eax], 0x5A4D
			je end
			sub eax, 0x00010000
			JMP find
			end :
		ret

	}
}


DWORD GetModuleSize(HMODULE hModule)
{
	if (hModule)
	{
		PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)hModule;
		PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)(pDOS->e_lfanew + (DWORD)hModule);
		if (pNT->Signature == IMAGE_NT_SIGNATURE && pDOS->e_magic == IMAGE_DOS_SIGNATURE)
		{
			return pNT->OptionalHeader.SizeOfImage;
		}
	}
	return 0;
}

void* GetProcAddress32(void * lvpBaseAddress, char * lpszProcName)
{
	if (lvpBaseAddress)
	{
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)((DWORD)lvpBaseAddress);
		PIMAGE_NT_HEADERS psNtHeader = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD)lvpBaseAddress);

		char * lpcModBase = (char *)lvpBaseAddress;
		PIMAGE_EXPORT_DIRECTORY psExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpcModBase +
			psNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		int nNumberOfNames = psExportDir->NumberOfNames;
		unsigned long * lpulFunctions =
			(unsigned long *)(lpcModBase + psExportDir->AddressOfFunctions);

		unsigned long * lpulNames =
			(unsigned long *)(lpcModBase + psExportDir->AddressOfNames);

		unsigned short * lpusOrdinals =
			(unsigned short *)(lpcModBase + psExportDir->AddressOfNameOrdinals);
		int i;
		char * lpszFunctionName;
		for (i = 0; i < nNumberOfNames; i++) {
			lpszFunctionName = ((__int8 *)lpulNames[i]) + (int)lvpBaseAddress;

			if (_strcmpi_a(lpszFunctionName, lpszProcName) == 0)
			{

				DWORD Offset = lpulFunctions[lpusOrdinals[i]];
				void* FunctionAddress = (void*)(Offset + (DWORD)lvpBaseAddress);

				if (Offset >= psNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
					&& Offset < (psNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + psNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
				{

					return 0;
				}

				return FunctionAddress;
			}
		}
	}
	return NULL;
}

void* GetModuleBase32(wchar_t* szModule)
{
	PPEB32 Peb = GetPEB();
	PPEB_LDR_DATA Ldr = Peb->Ldr;
	PLDR_DATA_TABLE_ENTRY DataEntryStart = (PLDR_DATA_TABLE_ENTRY)Ldr->InLoadOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY DataCurrent = DataEntryStart;

	if (szModule == NULL)
		return DataCurrent->DllBase;
	do
	{
		if (!_strcmpi_w(DataCurrent->BaseDllName.Buffer, szModule))
		{
			return DataCurrent->DllBase;
		}

		DataCurrent = (PLDR_DATA_TABLE_ENTRY)DataCurrent->InLoadOrderLinks.Flink;

	} while (DataEntryStart != DataCurrent && DataCurrent && DataCurrent->BaseDllName.Buffer);


	return NULL;
}


/*
Instead of using HeapAlloc we are directly calling RtlAllocateHeap
REMEMBER -> HeapAlloc is forwarded in kernel32.dll
*/
LPVOID MemoryAlloc(DWORD dwSize)
{
	LPVOID lpvHeap = NULL;

	RtlAllocateHeap_ RtlAllocateHeap = NULL;
	GetProcessHeap_ GetProcessHeap = NULL;

	/*Should we bypass hooks? No need!*/
	RtlAllocateHeap = (RtlAllocateHeap_)GetProcAddress32(GetModuleBase32(L"ntdll.dll"), "RtlAllocateHeap");
	GetProcessHeap = (GetProcessHeap_)GetProcAddress32(GetModuleBase32(L"kernel32.dll"), "GetProcessHeap");

	if (RtlAllocateHeap && GetProcessHeap)
	{
		lpvHeap = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
	}

	return lpvHeap;
}

BOOL MemoryFree(LPVOID lpvAllocBuffer)
{
	if (!lpvAllocBuffer) return FALSE;

	BOOL bRetValue = FALSE;

	RtlFreeHeap_ RtlFreeHeap = NULL;
	GetProcessHeap_ GetProcessHeap = NULL;
	HeapSize_ HeapSize = NULL;

	RtlFreeHeap = (RtlFreeHeap_)GetProcAddress32(GetModuleBase32(L"ntdll.dll"), "RtlFreeHeap");
	GetProcessHeap = (GetProcessHeap_)GetProcAddress32(GetModuleBase32(L"kernel32.dll"), "GetProcessHeap");
	HeapSize = (HeapSize_)GetProcAddress32(GetModuleBase32(L"kernel32.dll"), "HeapSize");


	if (GetProcessHeap) // Sanity check??
	{

		HANDLE hHeap = GetProcessHeap();

		if (HeapSize)
		{
			size_t blocksize = HeapSize(hHeap, 0, lpvAllocBuffer);

			if (blocksize != -1)
			{
				RtlSecureZeroMemory(lpvAllocBuffer, blocksize);
			}
		}


		if (RtlFreeHeap)
		{
			bRetValue = RtlFreeHeap(hHeap, 0, lpvAllocBuffer);

			lpvAllocBuffer = NULL;
		}
	}

	return bRetValue;
}