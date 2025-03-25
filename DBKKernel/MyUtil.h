#pragma once

#include <vadefs.h>
#include <intrin.h>
#include <stdio.h>

#include <ntifs.h>
// 署名权
// right to sign one's name on a piece of work
// PowerBy: LyShark
// Email: me@lyshark.com

#include <ntddk.h>


#define POOL_TAG 'MYDR'

#define Kd_IHVDRIVER_Mask 0x3fffffff
#define MyKdPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_INFO_LEVEL,"Attack FuncName = %s line = %d ",__FUNCTION__,__LINE__); \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_INFO_LEVEL,__VA_ARGS__)

#ifndef _WIN32 
typedef struct _LDR_DATA_TABLE_ENTRY32
{
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
    union {
        LIST_ENTRY32 HashLinks;
        struct {
            ULONG SectionPointer;
            ULONG  CheckSum;
        };
    };
    union {
        struct {
            ULONG  TimeDateStamp;
        };
        struct {
            ULONG LoadedImports;
        };
    };
} LDR_DATA_TABLE_ENTRY32, LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY,* PLDR_DATA_TABLE_ENTRY32;
#define CRACK \
PLDR_DATA_TABLE_ENTRY32 ldr;ldr = (PLDR_DATA_TABLE_ENTRY32)(pDriverObj->DriverSection);ldr->Flags |= 0x20;
#else
typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64    InLoadOrderLinks;
    LIST_ENTRY64    InMemoryOrderLinks;
    LIST_ENTRY64    InInitializationOrderLinks;
    PVOID            DllBase;
    PVOID            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING    FullDllName;
    UNICODE_STRING     BaseDllName;
    ULONG            Flags;
    USHORT            LoadCount;
    USHORT            TlsIndex;
    PVOID            SectionPointer;
    ULONG            CheckSum;
    PVOID            LoadedImports;
    PVOID            EntryPointActivationContext;
    PVOID            PatchInformation;
    LIST_ENTRY64    ForwarderLinks;
    LIST_ENTRY64    ServiceTagLinks;
    LIST_ENTRY64    StaticLinks;
    PVOID            ContextInformation;
    ULONG64            OriginalBase;
    LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY,* PLDR_DATA_TABLE_ENTRY64;
#define CRACK \
PLDR_DATA_TABLE_ENTRY64 ldr;ldr = (PLDR_DATA_TABLE_ENTRY64)(DriverObject->DriverSection);ldr->Flags |= 0x20;
#endif


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,             // obsolete...delete
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;



// -------------------------------------------------------
// 引用微软结构
// -------------------------------------------------------
// 结构体定义
typedef struct _HANDLE_INFO
{
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT  HandleValue;
    ULONG GrantedAccess;
    ULONG64 Object;
    UCHAR Name[256];
} HANDLE_INFO, * PHANDLE_INFO;

extern HANDLE_INFO HandleInfo[1024];

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT  UniqueProcessId;
    USHORT  CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT  HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG64 NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;



typedef struct _OBJECT_BASIC_INFORMATION
{
    ULONG                   Attributes;
    ACCESS_MASK             DesiredAccess;
    ULONG                   HandleCount;
    ULONG                   ReferenceCount;
    ULONG                   PagedPoolUsage;
    ULONG                   NonPagedPoolUsage;
    ULONG                   Reserved[3];
    ULONG                   NameInformationLength;
    ULONG                   TypeInformationLength;
    ULONG                   SecurityDescriptorLength;
    LARGE_INTEGER           CreationTime;
} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING          TypeName;
    ULONG                   TotalNumberOfHandles;
    ULONG                   TotalNumberOfObjects;
    WCHAR                   Unused1[8];
    ULONG                   HighWaterNumberOfHandles;
    ULONG                   HighWaterNumberOfObjects;
    WCHAR                   Unused2[8];
    ACCESS_MASK             InvalidAttributes;
    GENERIC_MAPPING         GenericMapping;
    ACCESS_MASK             ValidAttributes;
    BOOLEAN                 SecurityRequired;
    BOOLEAN                 MaintainHandleCount;
    USHORT                  MaintainTypeList;
    POOL_TYPE               PoolType;
    ULONG                   DefaultPagedPoolCharge;
    ULONG                   DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;



typedef struct _OBJECT_HANDLE_FLAG_INFORMATION
{
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
}OBJECT_HANDLE_FLAG_INFORMATION, * POBJECT_HANDLE_FLAG_INFORMATION;
typedef enum _MY_OBJECT_INFORMATION_CLASS
{
    MyObjectBasicInformation,
    ObjectNameInformation,
    MyObjectTypeInformation,
    ObjectAllInformation,
    ObjectDataInformation
} MY_OBJECT_INFORMATION_CLASS, * PMY_OBJECT_INFORMATION_CLASS;



// -------------------------------------------------------
// 导出函数定义
// -------------------------------------------------------

NTKERNELAPI NTSTATUS ObSetHandleAttributes
(
    HANDLE Handle,
    POBJECT_HANDLE_FLAG_INFORMATION HandleFlags,
    KPROCESSOR_MODE PreviousMode
);

NTKERNELAPI VOID KeStackAttachProcess
(
    PEPROCESS PROCESS,
    PKAPC_STATE ApcState
);

NTKERNELAPI VOID KeUnstackDetachProcess
(
    PKAPC_STATE ApcState
);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId
(
    IN HANDLE ProcessId,
    OUT PEPROCESS* Process
);



NTSYSAPI NTSTATUS NTAPI ZwDuplicateObject
(
    HANDLE    SourceProcessHandle,
    HANDLE    SourceHandle,
    HANDLE    TargetProcessHandle OPTIONAL,
    PHANDLE   TargetHandle OPTIONAL,
    ACCESS_MASK DesiredAccess,
    ULONG   HandleAttributes,
    ULONG   Options
);

NTSYSAPI NTSTATUS NTAPI ZwOpenProcess
(
    PHANDLE       ProcessHandle,
    ACCESS_MASK     AccessMask,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PCLIENT_ID      ClientId
);

_Must_inspect_result_ _IRQL_requires_max_(APC_LEVEL) NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);//驱动层调用未公开的API使用NTKERNELAPI关键字
NTKERNELAPI PEPROCESS IoThreadToProcess(_In_ PETHREAD Thread);//驱动层调用未公开的API使用NTKERNELAPI关键字
_IRQL_requires_max_(DISPATCH_LEVEL) NTKERNELAPI PEPROCESS IoGetCurrentProcess(VOID);//驱动层调用未公开的API使用NTKERNELAPI关键字
NTKERNELAPI char* PsGetProcessImageFileName(PEPROCESS Process);//驱动层调用未公开的API使用NTKERNELAPI关键字
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);


NTKERNELAPI NTSTATUS
PsSuspendThread(
    IN PETHREAD Thread,
    OUT PULONG PreviousSuspendCount OPTIONAL
);

NTKERNELAPI NTSTATUS
PsResumeThread(
    IN PETHREAD Thread,
    OUT PULONG PreviousSuspendCount OPTIONAL
);

NTKERNELAPI
NTSTATUS
PsGetContextThread(
    __in PETHREAD Thread,
    __inout PCONTEXT ThreadContext,
    __in KPROCESSOR_MODE Mode
);

NTKERNELAPI
NTSTATUS
PsSetContextThread(
    __in PETHREAD Thread,
    __in PCONTEXT ThreadContext,
    __in KPROCESSOR_MODE Mode
);

void ForceDeleteSelfDriverFile(PDRIVER_OBJECT  DriverObject);

void DumpDriverFile();


//新增一些内核PEB模块遍历相关代码

typedef struct _PEB_LDR_DATA                            // 9 elements, 0x58 bytes (sizeof) 
{
    /*0x000*/     ULONG32      Length;
    /*0x004*/     ULONG32        Padding;
    /*0x008*/     VOID* SsHandle;
    /*0x010*/     struct _LIST_ENTRY InLoadOrderModuleList;           // 2 elements, 0x10 bytes (sizeof) 
    /*0x020*/     struct _LIST_ENTRY InMemoryOrderModuleList;         // 2 elements, 0x10 bytes (sizeof) 
    /*0x030*/     struct _LIST_ENTRY InInitializationOrderModuleList; // 2 elements, 0x10 bytes (sizeof) 
    /*0x040*/     VOID* EntryInProgress;
    /*0x048*/     UINT8        ShutdownInProgress;
    /*0x049*/     UINT8        _PADDING1_[0x7];
    /*0x050*/     VOID* ShutdownThreadId;
}PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _MY_PEB                                                                                                                                                                                                                                                                                                                                                                                                              // 115 elements, 0x7C8 bytes (sizeof) 
{
                  VOID* Padding;
    /*0x008*/     VOID* Mutant;
    /*0x010*/     VOID* ImageBaseAddress;
    /*0x018*/     struct _PEB_LDR_DATA* Ldr;
}MY_PEB, * P_MY_PEB;
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);



#define SERIALPORT 0// 0x3F8//0x3ff8

typedef volatile struct _My_CriticalSection
{
    volatile __int64 locked;
    volatile int apicid;
    volatile int lockcount;
    char* name;
    int debuglevel;

} My_CriticalSection, * PMy_CriticalSection;

extern unsigned char inportb(unsigned int port);
extern void outportb(unsigned int port, unsigned char value);
extern void asm_spinlock(volatile __int64* lockvar);
void sendstringf(char* string, ...);
char waitforchar(void);
void sendstring(char* s);
BOOLEAN InitLog();
void UnInitLog();
int getAPICID(void);
void inner_csEnter(PMy_CriticalSection CS, int apicid);
void inner_csLeave(PMy_CriticalSection CS, int apicid);
#ifndef _WIN32
int vbuildstring(char* str, int size, char* string, va_list arglist);
#endif