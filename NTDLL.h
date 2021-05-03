#pragma once

#ifndef NTDLL_H_
#define NTDLL_H_


#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS 0x00000000


#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemProcessAndThreadInformation 5
#define 	OBJ_CASE_INSENSITIVE   0x00000040

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define DEREF( pointer )*(ULONG_PTR *)(pointer)

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
	    }
#endif

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;



typedef struct _LDR_MODULE
{
	LIST_ENTRY      InLoadOrderModuleList;
	LIST_ENTRY      InMemoryOrderModuleList;
	LIST_ENTRY      InInitializationOrderModuleList;
	PVOID           BaseAddress;
	PVOID           EntryPoint;
	ULONG           SizeOfImage;
	UNICODE_STRING  FullDllName;
	UNICODE_STRING  BaseDllName;
	ULONG           Flags;
	SHORT           LoadCount;
	SHORT           TlsIndex;
	LIST_ENTRY      HashTableEntry;
	ULONG           TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef LONG KPRIORITY;

typedef struct _CLIENT_ID {
	DWORD          UniqueProcess;
	DWORD          UniqueThread;
} CLIENT_ID;

typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG          WaitTime;
	PVOID          StartAddress;
	CLIENT_ID      ClientId;
	KPRIORITY      Priority;
	KPRIORITY      BasePriority;
	ULONG          ContextSwitchCount;
	LONG           State;
	LONG           WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef NTSTATUS(WINAPI *tNTQSI)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef struct _VM_COUNTERS {
#ifdef _WIN64
	SIZE_T         PeakVirtualSize;
	SIZE_T         PageFaultCount;
	SIZE_T         PeakWorkingSetSize;
	SIZE_T         WorkingSetSize;
	SIZE_T         QuotaPeakPagedPoolUsage;
	SIZE_T         QuotaPagedPoolUsage;
	SIZE_T         QuotaPeakNonPagedPoolUsage;
	SIZE_T         QuotaNonPagedPoolUsage;
	SIZE_T         PagefileUsage;
	SIZE_T         PeakPagefileUsage;
	SIZE_T         VirtualSize;
#else
	SIZE_T         PeakVirtualSize;
	SIZE_T         VirtualSize;
	ULONG          PageFaultCount;
	SIZE_T         PeakWorkingSetSize;
	SIZE_T         WorkingSetSize;
	SIZE_T         QuotaPeakPagedPoolUsage;
	SIZE_T         QuotaPagedPoolUsage;
	SIZE_T         QuotaPeakNonPagedPoolUsage;
	SIZE_T         QuotaNonPagedPoolUsage;
	SIZE_T         PagefileUsage;
	SIZE_T         PeakPagefileUsage;
#endif
} VM_COUNTERS;

typedef struct _SYSTEM_PROCESSES {
	ULONG            NextEntryDelta;
	ULONG            ThreadCount;
	ULONG            Reserved1[6];
	LARGE_INTEGER   CreateTime;
	LARGE_INTEGER   UserTime;
	LARGE_INTEGER   KernelTime;
	UNICODE_STRING  ProcessName;
	KPRIORITY        BasePriority;
	ULONG            ProcessId;
	ULONG            InheritedFromProcessId;
	ULONG            HandleCount;
	ULONG            Reserved2[2];
	VM_COUNTERS        VmCounters;
#if _WIN32_WINNT >= 0x500
	IO_COUNTERS        IoCounters;
#endif
	SYSTEM_THREADS  Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;


//
// ANSI strings are counted 8-bit character strings. If they are
// NULL terminated, Length does not include trailing NULL.
//

typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;

} STRING, *PSTRING;
//
// CURDIR structure
//

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;

} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG  TimeStamp;
	STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _SECTION_IMAGE_INFORMATION
{
	PVOID TransferAddress;
	ULONG ZeroBits;
	ULONG_PTR MaximumStackSize;
	ULONG_PTR CommittedStackSize;
	ULONG SubSystemType;
	union _SECTION_IMAGE_INFORMATION_u0
	{
		struct _SECTION_IMAGE_INFORMATION_s0
		{
			USHORT SubSystemMinorVersion;
			USHORT SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	ULONG GpValue;
	USHORT ImageCharacteristics;
	USHORT DllCharacteristics;
	USHORT Machine;
	BOOLEAN ImageContainsCode;
	BOOLEAN Spare1;
	ULONG LoaderFlags;
	ULONG Reserved[2];

} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;


typedef struct _RTL_USER_PROCESS_INFORMATION
{
	ULONG Length;
	HANDLE hProcess;
	HANDLE hThread;
	CLIENT_ID ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;

} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;                            // Should be set before call RtlCreateProcessParameters
	ULONG Length;                                   // Length of valid structure
	ULONG Flags;                                    // Currently only PPF_NORMALIZED (1) is known:
													//  - Means that structure is normalized by call RtlNormalizeProcessParameters
	ULONG DebugFlags;

	PVOID ConsoleHandle;                            // HWND to console window associated with process (if any).
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;                        // Specified in DOS-like symbolic link path, ex: "C:/WinNT/SYSTEM32"
	UNICODE_STRING DllPath;                         // DOS-like paths separated by ';' where system should search for DLL files.
	UNICODE_STRING ImagePathName;                   // Full path in DOS-like format to process'es file image.
	UNICODE_STRING CommandLine;                     // Command line
	PVOID Environment;                              // Pointer to environment block (see RtlCreateEnvironment)
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;                            // Fill attribute for console window
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;                     // Name of WindowStation and Desktop objects, where process is assigned
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[0x20];

} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

///// NATIVE API //////////

typedef NTSTATUS(NTAPI *NtOpenSection_)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *);

typedef NTSTATUS(WINAPI* NtCreateSection_)(
	_Out_     PHANDLE SectionHandle,
	_In_      ACCESS_MASK DesiredAccess,
	_In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_  PLARGE_INTEGER MaximumSize,
	_In_      ULONG SectionPageProtection,
	_In_      ULONG AllocationAttributes,
	_In_opt_  HANDLE FileHandle
	);

typedef NTSTATUS(WINAPI* NtMapViewOfSection_)(
	_In_         HANDLE SectionHandle,
	_In_         HANDLE ProcessHandle,
	_Inout_      PVOID *BaseAddress,
	_In_         ULONG_PTR ZeroBits,
	_In_         SIZE_T CommitSize,
	_Inout_opt_  PLARGE_INTEGER SectionOffset,
	_Inout_      PSIZE_T ViewSize,
	_In_         DWORD InheritDisposition,
	_In_         ULONG AllocationType,
	_In_         ULONG Win32Protect
	);


typedef NTSTATUS(WINAPI* NtUnmapViewOfSection_)(
	_In_      HANDLE ProcessHandle,
	_In_opt_  PVOID BaseAddress);


typedef NTSTATUS(WINAPI* NtClose_)(HANDLE Handle);

typedef LONG(NTAPI *NtResumeProcess_)(HANDLE ProcessHandle);

typedef NTSTATUS(NTAPI *NtWriteVirtualMemory_)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten);

typedef NTSTATUS(NTAPI *NtAllocateVirtualMemory_)(IN HANDLE   ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect);

typedef
BOOLEAN
(NTAPI
	*RtlDosPathNameToNtPathName_U_)(
		IN  PWSTR DosPathName,
		OUT PUNICODE_STRING NtPathName,
		OUT PWSTR * NtFileNamePart OPTIONAL,
		OUT PCURDIR DirectoryInfo OPTIONAL
		);

typedef
NTSTATUS
(NTAPI
	*RtlCreateProcessParameters_)(
		PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
		PUNICODE_STRING ImagePathName,
		PUNICODE_STRING DllPath,
		PUNICODE_STRING CurrentDirectory,
		PUNICODE_STRING CommandLine,
		PVOID Environment,
		PUNICODE_STRING WindowTitle,
		PUNICODE_STRING DesktopInfo,
		PUNICODE_STRING ShellInfo,
		PUNICODE_STRING RuntimeData
		);

typedef
NTSTATUS
(NTAPI
	*RtlCreateUserProcess_)(
		PUNICODE_STRING NtImagePathName,
		ULONG Attributes,
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
		PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
		PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
		HANDLE ParentProcess,
		BOOLEAN InheritHandles,
		HANDLE DebugPort,
		HANDLE ExceptionPort,
		PRTL_USER_PROCESS_INFORMATION ProcessInformation
		);

typedef
VOID
(NTAPI
	*RtlFreeUnicodeString_)(
		IN  PUNICODE_STRING UnicodeString
		);

typedef
NTSTATUS
(NTAPI
	*RtlDestroyProcessParameters_)(
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters
		);

typedef NTSTATUS(NTAPI *NtCreateTransaction_)(
	PHANDLE            TransactionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	LPGUID             Uow,
	HANDLE             TmHandle,
	ULONG              CreateOptions,
	ULONG              IsolationLevel,
	ULONG              IsolationFlags,
	PLARGE_INTEGER     Timeout,
	PUNICODE_STRING    Description
	);
typedef NTSTATUS(NTAPI* NtCreateProcessEx_)
(
	PHANDLE     ProcessHandle,
	ACCESS_MASK  DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
	HANDLE   ParentProcess,
	ULONG    Flags,
	HANDLE SectionHandle     OPTIONAL,
	HANDLE DebugPort     OPTIONAL,
	HANDLE ExceptionPort     OPTIONAL,
	BOOLEAN  InJob
	);
typedef NTSTATUS(NTAPI *NtRollbackTransaction_)(
	HANDLE  TransactionHandle,
	BOOLEAN Wait
	);


// rev
 
typedef NTSTATUS(
	
	NTAPI


	*NtSetContextThread_)(



		IN HANDLE               ThreadHandle,
		IN PCONTEXT             Context);


 // rev

typedef NTSTATUS(
	NTAPI


	*NtGetContextThread_)(



		IN HANDLE               ThreadHandle,
		OUT PCONTEXT            pContext);


#endif