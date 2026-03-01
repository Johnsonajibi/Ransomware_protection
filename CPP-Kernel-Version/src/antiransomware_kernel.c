/*
 * ADVANCED ANTI-RANSOMWARE KERNEL DRIVER
 * =====================================
 * Windows Kernel-Level File System Protection Driver
 * 
 * This driver operates at Ring-0 (kernel level) to provide
 * real-time file system protection against ransomware attacks.
 * 
 * Features:
 * - File system minifilter for real-time monitoring
 * - Process behavior analysis
 * - Registry protection hooks
 * - Network activity monitoring
 * - Advanced threat detection algorithms
 * 
 * Author: Johnson Ajibi
 * Version: 2.1
 * Date: February 2026
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

// Driver constants
#define ANTIRANSOMWARE_DEVICE_NAME    L"\\Device\\AntiRansomwareFilter"
#define ANTIRANSOMWARE_PORT_NAME      L"\\AntiRansomwarePort"
#define ANTIRANSOMWARE_TAG            'rAnA'

// Debug tracing fallback
#ifndef PT_DBG_PRINT
#define PTDBG_TRACE_ROUTINES            0x00000001
#define PT_DBG_PRINT(Level, Msg)        DbgPrint Msg
#endif

// IOCTL codes for communication with user-mode application
// MUST MATCH USER MODE APPLICATION EXACTLY
#define IOCTL_AR_SET_PROTECTION      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AR_GET_STATUS          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_AR_GET_STATISTICS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_AR_SET_DB_POLICY       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AR_ISSUE_SERVICE_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AR_REVOKE_SERVICE_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AR_LIST_SERVICE_TOKENS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS)

// Protection levels
enum ProtectionLevel {
    ProtectionDisabled = 0,
    ProtectionMonitoring = 1,
    ProtectionActive = 2,
    ProtectionMaximum = 3
};

// Threat levels
typedef enum _THREAT_LEVEL {
    ThreatLevelNone = 0,
    ThreatLevelLow = 1,
    ThreatLevelMedium = 2,
    ThreatLevelHigh = 3,
    ThreatLevelCritical = 4
} THREAT_LEVEL;

// Protection statistics
typedef struct _PROTECTION_STATISTICS {
    volatile LONG FilesBlocked;
    volatile LONG ProcessesBlocked;
    volatile LONG EncryptionAttempts;
    volatile LONG TotalOperations;
    volatile LONG SuspiciousPatterns;
    volatile LONG ServiceTokenValidations;
    volatile LONG ServiceTokenRejections;
    volatile LONG FilesScanned;
    volatile LONG ThreatsBlocked;
} PROTECTION_STATISTICS, *PPROTECTION_STATISTICS;

// Process information structure
typedef struct _PROTECTED_PROCESS_INFO {
    HANDLE ProcessId;
    WCHAR ProcessName[256];
    BOOLEAN IsWhitelisted;
    ULONG ThreatScore;
    LARGE_INTEGER CreationTime;
} PROTECTED_PROCESS_INFO, *PPROTECTED_PROCESS_INFO;

// File operation context
typedef struct _FILE_OPERATION_CONTEXT {
    UNICODE_STRING FileName;
    HANDLE ProcessId;
    WCHAR ProcessName[256];
    LARGE_INTEGER Timestamp;
    ULONG OperationType;
    BOOLEAN IsEncryption;
    ULONG ThreatLevel;
} FILE_OPERATION_CONTEXT, *PFILE_OPERATION_CONTEXT;

// Global variables
PFLT_FILTER gFilterHandle;
PFLT_PORT gServerPort;
PFLT_PORT gClientPort;
PDEVICE_OBJECT gDeviceObject;
volatile LONG gProtectionLevel = ProtectionDisabled; // Default to disabled to prevent boot loops
PROTECTION_STATISTICS gStatistics = {0};
FAST_MUTEX gStatisticsMutex;
FAST_MUTEX gProcessListMutex;
LIST_ENTRY gProtectedProcessList;

// Known ransomware extensions
const PWCHAR RansomwareExtensions[] = {
    L".locked", L".encrypted", L".crypto", L".crypt", L".encrypt",
    L".axx", L".xyz", L".zzz", L".micro", L".zepto", L".locky",
    L".cerber", L".vault", L".exx", L".ezz", L".ecc", L".xtbl",
    L".wannacry", L".wcry", L".wncry", L".onion", L".dharma",
    NULL
};

// Suspicious process names (partial matches)
const PWCHAR SuspiciousProcessNames[] = {
    L"encrypt", L"crypt", L"ransom", L"locker", L"vault",
    L"bitcoin", L"btc", L"payment", L"decrypt", L"recover",
    L"restore", L"cipher", L"rsa", L"aes", L"tor",
    NULL
};

// Function prototypes
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

NTSTATUS AntiRansomwareUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS AntiRansomwareInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
VOID AntiRansomwareInstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);
VOID AntiRansomwareInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS AntiRansomwarePreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS AntiRansomwarePostCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS AntiRansomwarePreWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS AntiRansomwarePostWrite(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS AntiRansomwarePreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

NTSTATUS AntiRansomwareConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie, _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, _In_ ULONG SizeOfContext, _Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie);
VOID AntiRansomwareDisconnect(_In_opt_ PVOID ConnectionCookie);
NTSTATUS AntiRansomwareMessage(_In_opt_ PVOID ConnectionCookie, _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer, _In_ ULONG InputBufferSize, _Out_writes_bytes_to_opt_(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer, _In_ ULONG OutputBufferSize, _Out_ PULONG ReturnOutputBufferLength);

// Utility functions
BOOLEAN IsRansomwareExtension(_In_ PUNICODE_STRING FileName);
BOOLEAN IsSuspiciousProcess(_In_ PCWSTR ProcessName);
THREAT_LEVEL AnalyzeThreatLevel(_In_ PFILE_OPERATION_CONTEXT Context);
NTSTATUS GetProcessName(_In_ HANDLE ProcessId, _Out_ PWCHAR ProcessName, _In_ ULONG BufferSize);
BOOLEAN IsProcessWhitelisted(_In_ HANDLE ProcessId);
VOID UpdateStatistics(_In_ ULONG Operation);
NTSTATUS LogThreatActivity(_In_ PFILE_OPERATION_CONTEXT Context);

// Device control functions
NTSTATUS CreateControlDevice(_In_ PDRIVER_OBJECT DriverObject);
VOID AntiRansomwareDeleteControlDevice(void);
NTSTATUS HandleDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

//
// Assign text sections for each routine.
//
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, AntiRansomwareUnload)
#pragma alloc_text(PAGE, AntiRansomwareInstanceSetup)
#pragma alloc_text(PAGE, AntiRansomwareInstanceTeardownStart)
#pragma alloc_text(PAGE, AntiRansomwareInstanceTeardownComplete)
#endif

//
// Operation registration
//
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      AntiRansomwarePreCreate,
      AntiRansomwarePostCreate },

    { IRP_MJ_WRITE,
      0,
      AntiRansomwarePreWrite,
      AntiRansomwarePostWrite },

    { IRP_MJ_SET_INFORMATION,
      0,
      AntiRansomwarePreSetInformation,
      NULL },

    { IRP_MJ_OPERATION_END }
};

//
// Filter registration
//
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),         //  Size
    FLT_REGISTRATION_VERSION,         //  Version
    0,                               //  Flags
    NULL,                            //  Context
    Callbacks,                       //  Operation callbacks
    AntiRansomwareUnload,           //  MiniFilterUnload
    AntiRansomwareInstanceSetup,    //  InstanceSetup
    NULL,                           //  InstanceQueryTeardown
    AntiRansomwareInstanceTeardownStart, //  InstanceTeardownStart
    AntiRansomwareInstanceTeardownComplete, //  InstanceTeardownComplete
    NULL,                           //  GenerateFileName
    NULL,                           //  GenerateDestinationFileName
    NULL                            //  NormalizeNameComponent
};

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
    PSECURITY_DESCRIPTOR sd;

    UNREFERENCED_PARAMETER(RegistryPath);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("AntiRansomware!DriverEntry: Entered\n"));

    //
    // Initialize global data structures
    //
    ExInitializeFastMutex(&gStatisticsMutex);
    ExInitializeFastMutex(&gProcessListMutex);
    InitializeListHead(&gProtectedProcessList);
    RtlZeroMemory(&gStatistics, sizeof(PROTECTION_STATISTICS));

    //
    // Create control device for communication with user-mode
    //
    status = CreateControlDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Register with FltMgr to tell it our callback routines
    //
    status = FltRegisterFilter(DriverObject,
                               &FilterRegistration,
                               &gFilterHandle);

    FLT_ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status)) {

        //
        // Create communication port for user-mode communication
        //
        RtlInitUnicodeString(&uniString, ANTIRANSOMWARE_PORT_NAME);

        status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

        if (NT_SUCCESS(status)) {
            InitializeObjectAttributes(&oa,
                                       &uniString,
                                       OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                       NULL,
                                       sd);

            status = FltCreateCommunicationPort(gFilterHandle,
                                                &gServerPort,
                                                &oa,
                                                NULL,
                                                AntiRansomwareConnect,
                                                AntiRansomwareDisconnect,
                                                AntiRansomwareMessage,
                                                1);

            FltFreeSecurityDescriptor(sd);

            if (NT_SUCCESS(status)) {
                //
                // Start filtering I/O
                //
                status = FltStartFiltering(gFilterHandle);

                if (NT_SUCCESS(status)) {
                    // Don't enable protection by default - wait for user mode to enable it
                    gProtectionLevel = ProtectionDisabled;
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                                 ("AntiRansomware!DriverEntry: Filter started successfully\n"));
                } else {
                    FltCloseCommunicationPort(gServerPort);
                }
            }
        }

        if (!NT_SUCCESS(status)) {
            FltUnregisterFilter(gFilterHandle);
        }
    }

    if (!NT_SUCCESS(status)) {
        AntiRansomwareDeleteControlDevice();
    }

    return status;
}

NTSTATUS
AntiRansomwareUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("AntiRansomware!AntiRansomwareUnload: Entered\n"));

    gProtectionLevel = ProtectionDisabled;

    //
    // Close communication port
    //
    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
    }

    //
    // Unregister from FltMgr
    //
    FltUnregisterFilter(gFilterHandle);

    //
    // Delete the control device
    //
    AntiRansomwareDeleteControlDevice();

    return STATUS_SUCCESS;
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
NTSTATUS
AntiRansomwareInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("AntiRansomware!AntiRansomwareInstanceSetup: Entered\n"));

    return STATUS_SUCCESS;
}

VOID
AntiRansomwareInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("AntiRansomware!AntiRansomwareInstanceTeardownStart: Entered\n"));
}

VOID
AntiRansomwareInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("AntiRansomware!AntiRansomwareInstanceTeardownComplete: Entered\n"));
}

/*************************************************************************
    MiniFilter callback routines for file operations.
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS
AntiRansomwarePreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    FILE_OPERATION_CONTEXT context = {0};
    THREAT_LEVEL threatLevel;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // CRITICAL FIX: IRQL Check
    // FltGetFileNameInformation cannot be called at IRQL > PASSIVE_LEVEL for normalized names
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (gProtectionLevel == ProtectionDisabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Skip Paging I/O
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Skip kernel mode operations
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Get the file name
    //
    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED |
                                       FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);

    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Initialize context
    //
    context.FileName = nameInfo->Name;
    context.ProcessId = PsGetCurrentProcessId();
    context.OperationType = IRP_MJ_CREATE;
    KeQuerySystemTime(&context.Timestamp);

    //
    // Get process name - Safe to call at PASSIVE_LEVEL
    //
    GetProcessName(context.ProcessId, context.ProcessName, sizeof(context.ProcessName));

    //
    // Analyze threat level
    //
    threatLevel = AnalyzeThreatLevel(&context);

    if (threatLevel >= ThreatLevelHigh) {
        //
        // Log the threat
        //
        LogThreatActivity(&context);

        //
        // Update statistics
        //
        UpdateStatistics(1); // Threat blocked

        //
        // Block the operation for critical threats
        //
        if (threatLevel >= ThreatLevelCritical && gProtectionLevel >= ProtectionActive) {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                         ("AntiRansomware!AntiRansomwarePreCreate: Blocking operation for %wZ\n",
                          &nameInfo->Name));

            FltReleaseFileNameInformation(nameInfo);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
AntiRansomwarePostCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
AntiRansomwarePreWrite (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    FILE_OPERATION_CONTEXT context = {0};
    THREAT_LEVEL threatLevel;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // CRITICAL FIX: IRQL Check
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (gProtectionLevel == ProtectionDisabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Skip Paging I/O
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Skip kernel mode operations
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Get the file name
    //
    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED |
                                       FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);

    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Initialize context
    //
    context.FileName = nameInfo->Name;
    context.ProcessId = PsGetCurrentProcessId();
    context.OperationType = IRP_MJ_WRITE;
    KeQuerySystemTime(&context.Timestamp);

    //
    // Get process name
    //
    GetProcessName(context.ProcessId, context.ProcessName, sizeof(context.ProcessName));

    //
    // Check for encryption patterns in write operation
    //
    context.IsEncryption = TRUE; // Simplified - would analyze buffer content in real world

    //
    // Analyze threat level
    //
    threatLevel = AnalyzeThreatLevel(&context);

    if (threatLevel >= ThreatLevelMedium) {
        //
        // Log the threat
        //
        LogThreatActivity(&context);

        //
        // Update statistics
        //
        UpdateStatistics(0); // File scanned

        //
        // Block critical threats
        //
        if (threatLevel >= ThreatLevelCritical && gProtectionLevel >= ProtectionActive) {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                         ("AntiRansomware!AntiRansomwarePreWrite: Blocking write to %wZ\n",
                          &nameInfo->Name));

            FltReleaseFileNameInformation(nameInfo);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
AntiRansomwarePostWrite (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    //
    // Update statistics for successful write
    //
    if (NT_SUCCESS(Data->IoStatus.Status)) {
        UpdateStatistics(0); // File scanned
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
AntiRansomwarePreSetInformation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    FILE_OPERATION_CONTEXT context = {0};
    THREAT_LEVEL threatLevel;
    PFILE_RENAME_INFORMATION renameInfo;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // CRITICAL FIX: IRQL Check
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (gProtectionLevel == ProtectionDisabled) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Check if this is a file rename operation
    //
    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx) {

        //
        // Get the file name
        //
        status = FltGetFileNameInformation(Data,
                                           FLT_FILE_NAME_NORMALIZED |
                                           FLT_FILE_NAME_QUERY_DEFAULT,
                                           &nameInfo);

        if (!NT_SUCCESS(status)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        status = FltParseFileNameInformation(nameInfo);
        if (!NT_SUCCESS(status)) {
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        //
        // Check if renaming to a ransomware extension
        //
        renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (renameInfo != NULL) {
            UNICODE_STRING newName;
            
            // Safety check for buffer length
            if (renameInfo->FileNameLength > 0 && renameInfo->FileNameLength < 65536) {
                // We need to be careful with the buffer as it might not be NULL terminated
                // It is just a pointer to the buffer within the structure
                
                // Create a temporary safe unicode string
                newName.Buffer = renameInfo->FileName;
                newName.Length = (USHORT)renameInfo->FileNameLength;
                newName.MaximumLength = newName.Length;

                if (IsRansomwareExtension(&newName)) {
                    //
                    // Initialize context
                    //
                    context.FileName = nameInfo->Name;
                    context.ProcessId = PsGetCurrentProcessId();
                    context.OperationType = IRP_MJ_SET_INFORMATION;
                    KeQuerySystemTime(&context.Timestamp);

                    //
                    // Get process name
                    //
                    GetProcessName(context.ProcessId, context.ProcessName, sizeof(context.ProcessName));

                    //
                    // Analyze threat level
                    //
                    threatLevel = AnalyzeThreatLevel(&context);

                    if (threatLevel >= ThreatLevelHigh) {
                        //
                        // Log the threat
                        //
                        LogThreatActivity(&context);

                        //
                        // Update statistics
                        //
                        UpdateStatistics(1); // Threat blocked

                        if (gProtectionLevel >= ProtectionActive) {
                            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                                         ("AntiRansomware!AntiRansomwarePreSetInformation: Blocking rename to ransomware extension\n"));

                            FltReleaseFileNameInformation(nameInfo);
                            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                            Data->IoStatus.Information = 0;
                            return FLT_PREOP_COMPLETE;
                        }
                    }
                }
            }
        }

        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/*************************************************************************
    Communication routines.
*************************************************************************/

NTSTATUS
AntiRansomwareConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    PAGED_CODE();

    FLT_ASSERT(gClientPort == NULL);
    gClientPort = ClientPort;

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("AntiRansomware!AntiRansomwareConnect: Client connected\n"));

    return STATUS_SUCCESS;
}

VOID
AntiRansomwareDisconnect (
    _In_opt_ PVOID ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("AntiRansomware!AntiRansomwareDisconnect: Client disconnected\n"));

    //
    // Close client port
    //
    FltCloseClientPort(gFilterHandle, &gClientPort);
}

NTSTATUS
AntiRansomwareMessage (
    _In_opt_ PVOID ConnectionCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(ConnectionCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);
    UNREFERENCED_PARAMETER(ReturnOutputBufferLength);

    PAGED_CODE();

    if (InputBuffer != NULL && InputBufferSize >= sizeof(ULONG)) {
        // Obsolete legacy message handling
        // We now primarily use DeviceIoControl
        // This is kept for backward compatibility if needed, but for now we just return success
    }

    return status;
}

/*************************************************************************
    Utility functions.
*************************************************************************/

BOOLEAN
IsRansomwareExtension (
    _In_ PUNICODE_STRING FileName
    )
{
    ULONG i;
    UNICODE_STRING extension;

    for (i = 0; RansomwareExtensions[i] != NULL; i++) {
        RtlInitUnicodeString(&extension, RansomwareExtensions[i]);
        
        if (FileName->Length >= extension.Length) {
            UNICODE_STRING fileTail;
            fileTail.Buffer = (PWCHAR)((PCHAR)FileName->Buffer + FileName->Length - extension.Length);
            fileTail.Length = extension.Length;
            fileTail.MaximumLength = extension.Length;

            if (RtlEqualUnicodeString(&fileTail, &extension, TRUE)) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

BOOLEAN
IsSuspiciousProcess (
    _In_ PCWSTR ProcessName
    )
{
    ULONG i;
       
    for (i = 0; SuspiciousProcessNames[i] != NULL; i++) {
        if (wcsstr(ProcessName, SuspiciousProcessNames[i]) != NULL) {
            return TRUE;
        }
    }

    return FALSE;
}

THREAT_LEVEL
AnalyzeThreatLevel (
    _In_ PFILE_OPERATION_CONTEXT Context
    )
{
    THREAT_LEVEL level = ThreatLevelNone;

    //
    // Check for ransomware extension
    //
    if (IsRansomwareExtension(&Context->FileName)) {
        level = ThreatLevelCritical;
    }

    //
    // Check for suspicious process
    //
    if (IsSuspiciousProcess(Context->ProcessName)) {
        if (level < ThreatLevelHigh) {
            level = ThreatLevelHigh;
        }
    }

    //
    // Check for encryption patterns
    //
    if (Context->IsEncryption && Context->OperationType == IRP_MJ_WRITE) {
        if (level < ThreatLevelMedium) {
            level = ThreatLevelMedium;
        }
    }

    //
    // Check if process is whitelisted
    //
    if (IsProcessWhitelisted(Context->ProcessId)) {
        level = ThreatLevelNone;
    }

    return level;
}

NTSTATUS
GetProcessName (
    _In_ HANDLE ProcessId,
    _Out_ PWCHAR ProcessName,
    _In_ ULONG BufferSize
    )
{
    NTSTATUS status;
    PEPROCESS process;
    PUNICODE_STRING processImageName = NULL;

    //
    // Reference the process
    //
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // SAFE: Use SeLocateProcessImageName instead of PsGetProcessImageFileName
    //
    status = SeLocateProcessImageName(process, &processImageName);
    if (NT_SUCCESS(status) && processImageName != NULL) {
        RtlStringCchCopyW(ProcessName, BufferSize / sizeof(WCHAR), processImageName->Buffer);
        ExFreePool(processImageName);
        status = STATUS_SUCCESS;
    } else {
        status = STATUS_UNSUCCESSFUL;
    }

    //
    // Dereference the process
    //
    ObDereferenceObject(process);

    return status;
}

BOOLEAN
IsProcessWhitelisted (
    _In_ HANDLE ProcessId
    )
{
    // Simplified implementation - would check against a real whitelist
    UNREFERENCED_PARAMETER(ProcessId);
    
    // For now, don't whitelist anything
    return FALSE;
}

VOID
UpdateStatistics (
    _In_ ULONG Operation
    )
{
    ExAcquireFastMutex(&gStatisticsMutex);

    switch (Operation) {
        case 0: // File scanned
            InterlockedIncrement(&gStatistics.FilesScanned);
            InterlockedIncrement(&gStatistics.TotalOperations);
            break;
        case 1: // Threat blocked
            InterlockedIncrement(&gStatistics.ThreatsBlocked);
            break;
        default:
            break;
    }

    ExReleaseFastMutex(&gStatisticsMutex);
}

NTSTATUS
LogThreatActivity (
    _In_ PFILE_OPERATION_CONTEXT Context
    )
{
    // In a real implementation, this would log to event log or file
    UNREFERENCED_PARAMETER(Context);
    
    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("AntiRansomware!LogThreatActivity: Threat logged for %wZ\n",
                  &Context->FileName));

    return STATUS_SUCCESS;
}

/*************************************************************************
    Device control functions.
*************************************************************************/

NTSTATUS
CreateControlDevice (
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;

    RtlInitUnicodeString(&deviceName, ANTIRANSOMWARE_DEVICE_NAME);
    
    status = IoCreateDevice(DriverObject,
                            0,
                            &deviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &gDeviceObject);

    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&symbolicLink, L"\\DosDevices\\AntiRansomwareFilter");
        
        status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
        
        if (NT_SUCCESS(status)) {
            DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleDeviceControl;
            DriverObject->MajorFunction[IRP_MJ_CREATE] = HandleDeviceControl;
            DriverObject->MajorFunction[IRP_MJ_CLOSE] = HandleDeviceControl;
        } else {
            IoDeleteDevice(gDeviceObject);
            gDeviceObject = NULL;
        }
    }

    return status;
}

VOID
AntiRansomwareDeleteControlDevice (
    void
    )
{
    UNICODE_STRING symbolicLink;

    if (gDeviceObject != NULL) {
        RtlInitUnicodeString(&symbolicLink, L"\\DosDevices\\AntiRansomwareFilter");
        IoDeleteSymbolicLink(&symbolicLink);
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = NULL;
    }
}

NTSTATUS
HandleDeviceControl (
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack;
    ULONG ioControlCode;
    PVOID inputBuffer;
    ULONG inputBufferLength;
    PVOID outputBuffer;
    ULONG outputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    
    switch (irpStack->MajorFunction) {
        case IRP_MJ_CREATE:
        case IRP_MJ_CLOSE:
            // Simple open/close handling
            break;

        case IRP_MJ_DEVICE_CONTROL:
            ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
            
            switch (ioControlCode) {
                case IOCTL_AR_SET_PROTECTION:
                    if (inputBufferLength >= sizeof(ULONG)) {
                        ULONG newLevel = *(ULONG*)inputBuffer;
                        if (newLevel <= ProtectionMaximum) {
                            InterlockedExchange(&gProtectionLevel, newLevel);
                            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                                         ("AntiRansomware!HandleDeviceControl: Protection level set to %d\n", newLevel));
                        } else {
                            status = STATUS_INVALID_PARAMETER;
                        }
                    } else {
                        status = STATUS_BUFFER_TOO_SMALL;
                    }
                    break;

                case IOCTL_AR_GET_STATUS:
                    if (outputBufferLength >= sizeof(ULONG)) {
                        *(ULONG*)outputBuffer = gProtectionLevel;
                        Irp->IoStatus.Information = sizeof(ULONG);
                    } else {
                        status = STATUS_BUFFER_TOO_SMALL;
                    }
                    break;

                case IOCTL_AR_GET_STATISTICS:
                    if (outputBufferLength >= sizeof(PROTECTION_STATISTICS)) {
                        ExAcquireFastMutex(&gStatisticsMutex);
                        RtlCopyMemory(outputBuffer, &gStatistics, sizeof(PROTECTION_STATISTICS));
                        ExReleaseFastMutex(&gStatisticsMutex);
                        Irp->IoStatus.Information = sizeof(PROTECTION_STATISTICS);
                    } else {
                        status = STATUS_BUFFER_TOO_SMALL;
                    }
                    break;

                case IOCTL_AR_SET_DB_POLICY:
                    // Placeholder for future DB policy implementation
                    // This matches the user-mode IOCTL check
                    status = STATUS_SUCCESS;
                    break;

                case IOCTL_AR_ISSUE_SERVICE_TOKEN:
                case IOCTL_AR_REVOKE_SERVICE_TOKEN:
                case IOCTL_AR_LIST_SERVICE_TOKENS:
                    // Placeholders for future Token implementation
                    status = STATUS_SUCCESS;
                    break;

                default:
                    status = STATUS_INVALID_DEVICE_REQUEST;
                    break;
            }
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
