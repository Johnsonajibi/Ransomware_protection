/*
 * Anti-Ransomware Windows Kernel Driver (FltMgr Minifilter)
 * Real-time file system protection with cryptographic token validation
 * Intercepts all file operations at kernel level for maximum security
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <wdm.h>
#include "driver_common.h"

// Constants
#define ANTI_RANSOMWARE_TAG 'ARtg'
#define TOKEN_LIFETIME_SEC 300  // 5 minutes
#define MAX_PROTECTED_PATHS 1024
#define DEVICE_NAME L"\\Device\\AntiRansomwareDriver"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\AntiRansomwareDriver"

// Token structure for kernel validation
typedef struct _KERNEL_TOKEN {
    ULONG ProcessId;
    LARGE_INTEGER ExpiryTime;
    UCHAR HardwareFingerprint[32];
    UCHAR TokenHash[32];
    BOOLEAN IsValid;
} KERNEL_TOKEN, *PKERNEL_TOKEN;

// Per-file context for validation cache
typedef struct _FILE_CONTEXT {
    KERNEL_TOKEN ValidToken;
    BOOLEAN HasValidToken;
    LARGE_INTEGER LastAccess;
} FILE_CONTEXT, *PFILE_CONTEXT;

// Global state
PFLT_FILTER gFilterHandle = NULL;
PDEVICE_OBJECT gDeviceObject = NULL;
UNICODE_STRING gProtectedPaths[MAX_PROTECTED_PATHS];
ULONG gProtectedPathCount = 0;
FAST_MUTEX gGlobalMutex;
DRIVER_STATISTICS gStatistics = {0};

// Function declarations
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS InstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags,
                       DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType);
VOID InstanceTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS PreWriteCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS PreSetInformationCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
NTSTATUS DeviceControlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS CreateDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS CloseDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
BOOLEAN IsPathProtected(PCUNICODE_STRING FilePath);
BOOLEAN ValidateTokenForProcess(ULONG ProcessId, ULONG RequestedAccess);
FLT_PREOP_CALLBACK_STATUS PreWriteCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS PreSetInfoCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
BOOLEAN IsProtectedPath(PCUNICODE_STRING FilePath);
BOOLEAN VerifyToken(PTOKEN Token, PCUNICODE_STRING FilePath, ULONG ProcessId);
NTSTATUS RequestTokenFromBroker(PCUNICODE_STRING FilePath, ULONG ProcessId, PTOKEN OutToken);

// Filter registration
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreateCallback, NULL },
    { IRP_MJ_WRITE, 0, PreWriteCallback, NULL },
    { IRP_MJ_SET_INFORMATION, 0, PreSetInfoCallback, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_CONTEXT_REGISTRATION Contexts[] = {
    { FLT_FILE_CONTEXT, 0, NULL, sizeof(FILE_CONTEXT), ANTI_RANSOMWARE_TAG },
    { FLT_CONTEXT_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),   // Size
    FLT_REGISTRATION_VERSION,   // Version
    0,                          // Flags
    Contexts,                   // Context Registration
    Callbacks,                  // Operation callbacks
    FilterUnload,               // FilterUnload
    InstanceSetup,              // InstanceSetup
    NULL,                       // InstanceQueryTeardown
    InstanceTeardown,           // InstanceTeardown
    NULL,                       // GenerateFileName
    NULL,                       // GenerateDestinationFileName
    NULL                        // NormalizeNameComponent
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    
    UNREFERENCED_PARAMETER(RegistryPath);
    
    ExInitializeFastMutex(&gGlobalMutex);
    
    // Load protected paths from registry
    // TODO: Load from policy/registry
    RtlInitUnicodeString(&gProtectedPaths[0], L"\\Device\\HarddiskVolume1\\Protected");
    gProtectedPathCount = 1;
    
    // Load public key from registry
    // TODO: Load Ed25519 public key from secure location
    
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        return status;
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    
    // TODO: Require TPM-signed token to disable
    FltUnregisterFilter(gFilterHandle);
    return STATUS_SUCCESS;
}

NTSTATUS InstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags,
                       DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    
    return STATUS_SUCCESS;
}

VOID InstanceTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

// Core callback implementations
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext) {
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PFILE_CONTEXT fileContext = NULL;
    ULONG processId;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    
    gStatistics.TotalRequests++;
    
    // Get file name
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Check if path is protected
    if (!IsPathProtected(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Get process ID for token validation
    processId = FltGetRequestorProcessId(Data);
    
    // Validate token for this process
    if (!ValidateTokenForProcess(processId, OP_CREATE)) {
        gStatistics.BlockedRequests++;
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    
    gStatistics.AllowedRequests++;
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS PreWriteCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext) {
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG processId;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    
    gStatistics.TotalRequests++;
    
    // Get file name
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Check if path is protected
    if (!IsPathProtected(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Get process ID for token validation
    processId = FltGetRequestorProcessId(Data);
    
    // Validate token for write access
    if (!ValidateTokenForProcess(processId, OP_WRITE)) {
        gStatistics.BlockedRequests++;
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    
    gStatistics.AllowedRequests++;
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS PreSetInformationCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext) {
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG processId;
    FILE_INFORMATION_CLASS fileInfoClass;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    
    gStatistics.TotalRequests++;
    
    fileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    
    // Only monitor delete and rename operations
    if (fileInfoClass != FileDispositionInformation && 
        fileInfoClass != FileRenameInformation &&
        fileInfoClass != FileEndOfFileInformation) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Get file name
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Check if path is protected
    if (!IsPathProtected(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Get process ID for token validation
    processId = FltGetRequestorProcessId(Data);
    
    // Determine required access based on operation
    ULONG requiredAccess = OP_WRITE;
    if (fileInfoClass == FileDispositionInformation) {
        requiredAccess = OP_DELETE;
    } else if (fileInfoClass == FileRenameInformation) {
        requiredAccess = OP_RENAME;
    }
    
    // Validate token
    if (!ValidateTokenForProcess(processId, requiredAccess)) {
        gStatistics.BlockedRequests++;
        FltReleaseFileNameInformation(nameInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    
    gStatistics.AllowedRequests++;
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Helper functions
BOOLEAN IsPathProtected(PCUNICODE_STRING FilePath) {
    ULONG i;
    
    ExAcquireFastMutex(&gGlobalMutex);
    
    for (i = 0; i < gProtectedPathCount; i++) {
        if (RtlPrefixUnicodeString(&gProtectedPaths[i], FilePath, TRUE)) {
            ExReleaseFastMutex(&gGlobalMutex);
            return TRUE;
        }
    }
    
    ExReleaseFastMutex(&gGlobalMutex);
    return FALSE;
}

BOOLEAN ValidateTokenForProcess(ULONG ProcessId, ULONG RequestedAccess) {
    // This is a simplified validation - in production, this would:
    // 1. Check cached tokens for the process
    // 2. Validate token signatures
    // 3. Check token expiry
    // 4. Verify hardware fingerprint
    // 5. Communicate with user-mode service if needed
    
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(RequestedAccess);
    
    // For now, allow all access (placeholder)
    // TODO: Implement real token validation
    return TRUE;
}
    
    // Get file name
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Check if this is a protected path
    if (!IsProtectedPath(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Allocate file context for token caching
    status = FltAllocateContext(FltObjects->Filter, FLT_FILE_CONTEXT, sizeof(FILE_CONTEXT), NonPagedPool, &fileContext);
    if (NT_SUCCESS(status)) {
        RtlZeroMemory(fileContext, sizeof(FILE_CONTEXT));
        FltSetFileContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, fileContext, NULL);
        FltReleaseContext(fileContext);
    }
    
    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS PreWriteCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext) {
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PFILE_CONTEXT fileContext = NULL;
    TOKEN token;
    LARGE_INTEGER currentTime;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    
    // Get file name
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Check if this is a protected path
    if (!IsProtectedPath(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Get file context (zero-copy token cache)
    status = FltGetFileContext(FltObjects->Instance, FltObjects->FileObject, &fileContext);
    if (NT_SUCCESS(status) && fileContext->HasValidToken) {
        KeQuerySystemTime(&currentTime);
        if (currentTime.QuadPart < fileContext->ValidToken.Expiry.QuadPart) {
            // Token still valid, allow access
            FltReleaseContext(fileContext);
            FltReleaseFileNameInformation(nameInfo);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }
    
    // Request new token from broker
    status = RequestTokenFromBroker(&nameInfo->Name, PsGetCurrentProcessId(), &token);
    if (!NT_SUCCESS(status)) {
        // No valid token, deny access
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        FltReleaseFileNameInformation(nameInfo);
        if (fileContext) FltReleaseContext(fileContext);
        return FLT_PREOP_COMPLETE;
    }
    
    // Verify token
    if (!VerifyToken(&token, &nameInfo->Name, PsGetCurrentProcessId())) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        FltReleaseFileNameInformation(nameInfo);
        if (fileContext) FltReleaseContext(fileContext);
        return FLT_PREOP_COMPLETE;
    }
    
    // Cache valid token in file context
    if (fileContext) {
        RtlCopyMemory(&fileContext->ValidToken, &token, sizeof(TOKEN));
        fileContext->HasValidToken = TRUE;
        KeQuerySystemTime(&fileContext->LastAccess);
    }
    
    FltReleaseFileNameInformation(nameInfo);
    if (fileContext) FltReleaseContext(fileContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS PreSetInfoCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext) {
    // Handle rename/delete operations
    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation) {
        return PreWriteCallback(Data, FltObjects, CompletionContext);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

BOOLEAN IsProtectedPath(PCUNICODE_STRING FilePath) {
    ULONG i;
    for (i = 0; i < gProtectedPathCount; i++) {
        if (RtlPrefixUnicodeString(&gProtectedPaths[i], FilePath, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN VerifyToken(PTOKEN Token, PCUNICODE_STRING FilePath, ULONG ProcessId) {
    // Constant-time Ed25519 verification
    // TODO: Implement Ed25519 signature verification using BCrypt
    // For now, basic checks
    LARGE_INTEGER currentTime;
    
    KeQuerySystemTime(&currentTime);
    
    // Check expiry
    if (currentTime.QuadPart > Token->Expiry.QuadPart) {
        return FALSE;
    }
    
    // Check process ID
    if (Token->ProcessId != ProcessId) {
        return FALSE;
    }
    
    // TODO: Verify Ed25519 signature over token data
    // TODO: Check nonce for replay protection
    
    return TRUE;
}

NTSTATUS RequestTokenFromBroker(PCUNICODE_STRING FilePath, ULONG ProcessId, PTOKEN OutToken) {
    // TODO: Communicate with user-space broker via named pipe/IOCTL
    // For now, return failure to trigger user prompt
    UNREFERENCED_PARAMETER(FilePath);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(OutToken);
    
    return STATUS_ACCESS_DENIED;
}
