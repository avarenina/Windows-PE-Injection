#pragma once
void GetImageBase();
DWORD GetModuleSize(HMODULE hModule);

void* GetProcAddress32(void * lvpBaseAddress, char * lpszProcName);
void* GetModuleBase32(wchar_t* szModule);

LPVOID MemoryAlloc(DWORD dwSize);
BOOL MemoryFree(LPVOID lpvAllocBuffer);


typedef struct _PEB_LDR_DATA {
	DWORD dwLength;
	DWORD Initialized;
	DWORD ssHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN Spare;
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
}PEB32, *PPEB32;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;