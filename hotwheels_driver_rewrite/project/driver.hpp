#pragma once

#include <ntifs.h>

#include <ntddk.h>
#include <ntstrsafe.h>

struct READ_MEMORY_CALLBACK_INPUT {
	HANDLE pid;
	PVOID address;
	SIZE_T size;

	PVOID memory_pointer;
};

struct WRITE_MEMORY_CALLBACK_INPUT {
	HANDLE pid;
	PVOID address;
	SIZE_T size;

	PVOID memory_pointer;
};

struct BASE_ADDRESS_CALLBACK_INPUT {
	HANDLE pid;
	ULONG64 hash;

	ULONG64 response;
};

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, *PPEB;

typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB32 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, *PPEB32;

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	UINT32 ExceptionTableSize;
	PVOID GpValue;
	struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
	PVOID ImageBase;
	PVOID EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullImageName;
	UNICODE_STRING BaseImageName;
	UINT32 Flags;
	UINT16 LoadCount;

	union {
		UINT16 SignatureLevel : 4;
		UINT16 SignatureType  : 3;
		UINT16 Unused         : 9;
		UINT16 EntireField;
	} u;

	PVOID SectionPointer;
	UINT32 CheckSum;
	UINT32 CoverageSectionSize;
	PVOID CoverageSection;
	PVOID LoadedImports;
	PVOID Spare;
	UINT32 SizeOfImageNotRounded;
	UINT32 TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

typedef struct _OB_REG_CONTEXT {
	USHORT Version;
	UNICODE_STRING Altitude;
	USHORT ulIndex;
	OB_OPERATION_REGISTRATION* OperationRegistration;
} REG_CONTEXT, *PREG_CONTEXT;

extern "C" NTKERNELAPI NTSTATUS IoCreateDriver( PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction );
extern "C" NTKERNELAPI VOID IoDeleteDriver( IN PDRIVER_OBJECT DriverObject );
extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process( PEPROCESS Process );
extern "C" NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory( PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress,
                                                           SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize );
extern "C" NTKERNELAPI PEB* NTAPI PsGetProcessPeb( PEPROCESS Process );

#define create_driver                 IoCreateDriver
#define create_device                 IoCreateDevice
#define create_symbolic_link          IoCreateSymbolicLink
#define current_irp_stack_location    IoGetCurrentIrpStackLocation
#define lookup_process_by_process_id  PsLookupProcessByProcessId
#define copy_virtual_memory           MmCopyVirtualMemory
#define get_process_wow64_process     PsGetProcessWow64Process
#define compare_unicode_string        RtlCompareUnicodeString
#define set_load_image_notify_routine PsSetLoadImageNotifyRoutine
#define get_process_peb               PsGetProcessPeb
#define delete_driver                 IoDeleteDriver
#define get_device_object_pointer     IoGetDeviceObjectPointer
#define device_io_control             FsRtlIssueDeviceIoControl
#define delete_symbolic_link          IoDeleteSymbolicLink
#define delete_device                 IoDeleteDevice
#define random                        RtlRandomEx
#define query_system_time_precise     KeQuerySystemTimePrecise
#define register_callbacks            ObRegisterCallbacks
#define attach_process                KeAttachProcess
#define detach_process                KeDetachProcess
#define string_cb_printf              RtlStringCbPrintfA

// Macro macro bitchhhh
#define get_current_process PsGetCurrentProcess

#ifdef _DEBUG
#	define dbg_print( string, ... ) DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, string, __VA_ARGS__ );
#else
#	define dbg_print( string, ... ) 
#endif

// If a variable we use from usermode gets "corrupted" we NEED to make sure it isn't above the x86 maxiumum address. This will cause a BSOD!
#define x86( address ) ( reinterpret_cast< ULONG64 >( address ) <= 0xFFFFFFFF )

constexpr int IOCTL_WRITE_MEMORY = CTL_CODE( FILE_DEVICE_UNKNOWN, ( 0x800 + 2 ), METHOD_BUFFERED, FILE_SPECIAL_ACCESS );
constexpr int IOCTL_READ_MEMORY  = CTL_CODE( FILE_DEVICE_UNKNOWN, ( 0x800 + 3 ), METHOD_BUFFERED, FILE_SPECIAL_ACCESS );
constexpr int IOCTL_BASE_ADDRESS = CTL_CODE( FILE_DEVICE_UNKNOWN, ( 0x800 + 4 ), METHOD_BUFFERED, FILE_SPECIAL_ACCESS );
constexpr int IOCTL_UNLOAD       = CTL_CODE( FILE_DEVICE_UNKNOWN, ( 0x800 + 5 ), METHOD_BUFFERED, FILE_SPECIAL_ACCESS );
