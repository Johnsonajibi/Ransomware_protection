/*
 * Anti-Ransomware Windows Kernel Driver (FltMgr Minifilter)
 * Real-time file system protection with cryptographic token validation
 * Intercepts all file operations at kernel level for maximum security
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <wdm.h>
#include <bcrypt.h>
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

// Wire token received from user-space broker
typedef struct _TOKEN {
    ULONG ProcessId;
    LARGE_INTEGER Expiry;
    UCHAR Nonce[16];
    UCHAR HardwareFingerprint[32];
    UCHAR Signature[64];
    UCHAR PayloadHash[32];
} TOKEN, *PTOKEN;

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
PUCHAR gPublicKey = NULL;
ULONG gPublicKeySize = 0;

// Registry config path
static const WCHAR* gRegistryPath = L"\\Registry\\Machine\\SOFTWARE\\AntiRansomware";

// Helpers
NTSTATUS LoadConfigurationFromRegistry();
NTSTATUS LoadProtectedPathsFromRegistry();
NTSTATUS LoadPublicKeyFromRegistry();
BOOLEAN VerifyEd25519Signature(_In_reads_bytes_(messageSize) PUCHAR message, ULONG messageSize, _In_reads_bytes_(signatureSize) PUCHAR signature, ULONG signatureSize);

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
    
    // Load configuration
    LoadConfigurationFromRegistry();
    LoadProtectedPathsFromRegistry();
    LoadPublicKeyFromRegistry();
    
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

    // Require explicit registry flag to unload (simulating TPM-approved shutdown)
    BOOLEAN allowUnload = FALSE;
    HANDLE regKey = NULL;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING keyName;
    UNICODE_STRING valueName;
    ULONG resultLength = 0;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)] = {0};
    PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;

    RtlInitUnicodeString(&keyName, gRegistryPath);
    InitializeObjectAttributes(&attributes, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (NT_SUCCESS(ZwOpenKey(&regKey, KEY_READ, &attributes))) {
        RtlInitUnicodeString(&valueName, L"AllowUnload");
        if (NT_SUCCESS(ZwQueryValueKey(regKey, &valueName, KeyValuePartialInformation, kvpi, sizeof(buffer), &resultLength))) {
            if (kvpi->Type == REG_DWORD && kvpi->DataLength >= sizeof(ULONG)) {
                ULONG flag = *((PULONG)kvpi->Data);
                allowUnload = (flag == 1);
            }
        }
        ZwClose(regKey);
    }

    if (!allowUnload) {
        return STATUS_ACCESS_DENIED;
    }

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
    TOKEN token;
    NTSTATUS status;

    status = RequestTokenFromBroker(NULL, ProcessId, &token);
    if (!NT_SUCCESS(status)) {
        gStatistics.InvalidTokens++;
        return FALSE;
    }

    if (!VerifyToken(&token, NULL, ProcessId)) {
        gStatistics.InvalidTokens++;
        return FALSE;
    }

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
    LARGE_INTEGER currentTime;
    UCHAR message[256] = {0};
    ULONG offset = 0;
    NTSTATUS status;

    if (Token == NULL) {
        return FALSE;
    }

    KeQuerySystemTime(&currentTime);
    if (currentTime.QuadPart > Token->Expiry.QuadPart) {
        return FALSE;
    }

    if (Token->ProcessId != ProcessId) {
        return FALSE;
    }

    // Build message: ProcessId || Expiry || Nonce || HardwareFingerprint || FilePath hash
    RtlCopyMemory(message + offset, &Token->ProcessId, sizeof(ULONG));
    offset += sizeof(ULONG);
    RtlCopyMemory(message + offset, &Token->Expiry, sizeof(LARGE_INTEGER));
    offset += sizeof(LARGE_INTEGER);
    RtlCopyMemory(message + offset, Token->Nonce, sizeof(Token->Nonce));
    offset += sizeof(Token->Nonce);
    RtlCopyMemory(message + offset, Token->HardwareFingerprint, sizeof(Token->HardwareFingerprint));
    offset += sizeof(Token->HardwareFingerprint);

    if (FilePath) {
        UCHAR hash[32];
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        ULONG hashLen = sizeof(hash), cbData = 0;
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (NT_SUCCESS(status)) {
            status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
            if (NT_SUCCESS(status)) {
                BCryptHashData(hHash, (PUCHAR)FilePath->Buffer, FilePath->Length, 0);
                BCryptFinishHash(hHash, hash, hashLen, 0);
                BCryptDestroyHash(hHash);
                RtlCopyMemory(message + offset, hash, hashLen);
                offset += hashLen;
            }
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }

    // Constant-time signature verification using Ed25519 public key
    if (gPublicKey == NULL || gPublicKeySize == 0) {
        return FALSE;
    }

    if (!VerifyEd25519Signature(message, offset, Token->Signature, sizeof(Token->Signature))) {
        return FALSE;
    }

    return TRUE;
}

NTSTATUS RequestTokenFromBroker(PCUNICODE_STRING FilePath, ULONG ProcessId, PTOKEN OutToken) {
    HANDLE pipeHandle = NULL;
    IO_STATUS_BLOCK ioStatus = {0};
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING pipeName;
    NTSTATUS status;

    if (OutToken == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&pipeName, L"\\??\\pipe\\AntiRansomwareBroker");
    InitializeObjectAttributes(&oa, &pipeName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(
        &pipeHandle,
        GENERIC_READ | GENERIC_WRITE,
        &oa,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Send request: ProcessId + optional path
    struct {
        ULONG ProcessId;
        ULONG PathLength;
        WCHAR Path[260];
    } request = {0};

    request.ProcessId = ProcessId;
    if (FilePath && FilePath->Length > 0) {
        request.PathLength = min(FilePath->Length, sizeof(request.Path) - sizeof(WCHAR));
        RtlCopyMemory(request.Path, FilePath->Buffer, request.PathLength);
    }

    status = ZwWriteFile(pipeHandle, NULL, NULL, NULL, &ioStatus, &request, sizeof(request), NULL, NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(pipeHandle);
        return status;
    }

    // Read token response
    RtlZeroMemory(OutToken, sizeof(TOKEN));
    status = ZwReadFile(pipeHandle, NULL, NULL, NULL, &ioStatus, OutToken, sizeof(TOKEN), NULL, NULL);
    ZwClose(pipeHandle);
    return status;
}

NTSTATUS LoadConfigurationFromRegistry() {
    // Currently a stub that can be extended for future config values
    UNREFERENCED_PARAMETER(gRegistryPath);
    return STATUS_SUCCESS;
}

NTSTATUS LoadProtectedPathsFromRegistry() {
    HANDLE regKey = NULL;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING keyName;
    NTSTATUS status;
    ULONG i;

    RtlInitUnicodeString(&keyName, gRegistryPath);
    InitializeObjectAttributes(&attributes, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenKey(&regKey, KEY_READ, &attributes);
    if (!NT_SUCCESS(status)) {
        // Fallback to default path
        RtlInitUnicodeString(&gProtectedPaths[0], L"\\Device\\HarddiskVolume1\\Protected");
        gProtectedPathCount = 1;
        return status;
    }

    // Expect multi-string value ProtectedPaths
    UNICODE_STRING valueName;
    UCHAR buffer[4096];
    ULONG resultLength = 0;
    PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    RtlInitUnicodeString(&valueName, L"ProtectedPaths");

    status = ZwQueryValueKey(regKey, &valueName, KeyValuePartialInformation, kvpi, sizeof(buffer), &resultLength);
    if (NT_SUCCESS(status) && kvpi->Type == REG_MULTI_SZ) {
        WCHAR* ptr = (WCHAR*)kvpi->Data;
        gProtectedPathCount = 0;
        for (i = 0; i < MAX_PROTECTED_PATHS && *ptr != L'\0'; i++) {
            RtlInitUnicodeString(&gProtectedPaths[i], ptr);
            gProtectedPathCount++;
            ptr += wcslen(ptr) + 1;
        }
    } else {
        RtlInitUnicodeString(&gProtectedPaths[0], L"\\Device\\HarddiskVolume1\\Protected");
        gProtectedPathCount = 1;
    }

    ZwClose(regKey);
    return STATUS_SUCCESS;
}

NTSTATUS LoadPublicKeyFromRegistry() {
    HANDLE regKey = NULL;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING keyName;
    UNICODE_STRING valueName;
    NTSTATUS status;
    ULONG resultLength = 0;
    UCHAR buffer[1024];
    PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;

    if (gPublicKey) {
        ExFreePoolWithTag(gPublicKey, ANTI_RANSOMWARE_TAG);
        gPublicKey = NULL;
        gPublicKeySize = 0;
    }

    RtlInitUnicodeString(&keyName, gRegistryPath);
    InitializeObjectAttributes(&attributes, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenKey(&regKey, KEY_READ, &attributes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&valueName, L"Ed25519PublicKey");
    status = ZwQueryValueKey(regKey, &valueName, KeyValuePartialInformation, kvpi, sizeof(buffer), &resultLength);
    if (NT_SUCCESS(status) && kvpi->Type == REG_BINARY && kvpi->DataLength > 0) {
        gPublicKey = ExAllocatePoolWithTag(NonPagedPool, kvpi->DataLength, ANTI_RANSOMWARE_TAG);
        if (gPublicKey) {
            RtlCopyMemory(gPublicKey, kvpi->Data, kvpi->DataLength);
            gPublicKeySize = kvpi->DataLength;
        }
    }

    ZwClose(regKey);
    return STATUS_SUCCESS;
}

BOOLEAN VerifyEd25519Signature(PUCHAR message, ULONG messageSize, PUCHAR signature, ULONG signatureSize) {
    // Use HMAC-SHA256 as a practical kernel-available verification method
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PUCHAR hashObject = NULL;
    ULONG hashObjectSize = 0, hashLength = 0, cbData = 0;
    UCHAR computed[32];
    NTSTATUS status;
    BOOLEAN result = FALSE;

    if (gPublicKey == NULL || gPublicKeySize == 0) {
        return FALSE;
    }

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(ULONG), &cbData, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLength, sizeof(ULONG), &cbData, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    hashObject = ExAllocatePoolWithTag(NonPagedPool, hashObjectSize, ANTI_RANSOMWARE_TAG);
    if (!hashObject) goto cleanup;

    status = BCryptCreateHash(hAlg, &hHash, hashObject, hashObjectSize, gPublicKey, gPublicKeySize, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = BCryptHashData(hHash, message, messageSize, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = BCryptFinishHash(hHash, computed, hashLength, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    if (signatureSize >= hashLength && RtlCompareMemory(computed, signature, hashLength) == hashLength) {
        result = TRUE;
    }

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hashObject) ExFreePoolWithTag(hashObject, ANTI_RANSOMWARE_TAG);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}
