/*
 * AntiRansomware Minifilter Driver
 * Windows Filter Driver to intercept and block file I/O operations on protected paths
 * Requires Windows Driver Kit (WDK) to compile
 * 
 * Compilation: msbuild AntiRansomwareFilter.vcxproj /p:Configuration=Release /p:Platform=x64
 */

#include <fltkernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_UNUSED_FUNCTION, "Template-generated code")

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

// Minifilter callbacks
FLT_PREOP_CALLBACK_STATUS PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS PostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS PreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS PreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

// Global data
PFLT_FILTER gFilterHandle = NULL;
ULONG_PTR OperationStatusCtx = 1;

// Protected paths (configurable via registry)
#define MAX_PROTECTED_PATHS 10
WCHAR gProtectedPaths[MAX_PROTECTED_PATHS][MAX_PATH] = {0};
ULONG gProtectedPathCount = 0;

// Operation registration
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      PreCreate,
      PostCreate },

    { IRP_MJ_WRITE,
      0,
      PreWrite,
      NULL },

    { IRP_MJ_SET_INFORMATION,
      0,
      PreSetInformation,
      NULL },

    { IRP_MJ_OPERATION_END }
};

// Filter registration
const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),        // Size
    FLT_REGISTRATION_VERSION,        // Version
    0,                               // Flags
    NULL,                            // ContextRegistration
    Callbacks,                        // Operation callbacks
    NULL,                            // FilterUnloadCallback
    NULL,                            // InstanceSetupCallback
    NULL,                            // InstanceQueryTeardownCallback
    NULL,                            // InstanceTeardownStartCallback
    NULL,                            // InstanceTeardownCompleteCallback
    NULL,                            // GenerateFileNameCallback
    NULL,                            // NormalizeNameComponentCallback
    NULL,                            // NormalizeContextCleanupCallback
    NULL,                            // TransactionNotificationCallback
    NULL,                            // NormalizeNameComponentExCallback
};

// Check if a path is protected
BOOLEAN IsPathProtected(PUNICODE_STRING FilePath)
{
    ULONG i;
    UNICODE_STRING protectedPath;
    
    for (i = 0; i < gProtectedPathCount; i++) {
        RtlInitUnicodeString(&protectedPath, gProtectedPaths[i]);
        
        // Check if FilePath starts with protected path
        if (FilePath->Length >= protectedPath.Length &&
            RtlEqualUnicodeString(&protectedPath, 
                                 (PUNICODE_STRING)RtlOffsetToPointer(FilePath, 0),
                                 TRUE)) {
            return TRUE;
        }
    }
    
    return FALSE;
}

// Pre-Create callback: Block file open attempts on protected paths
FLT_PREOP_CALLBACK_STATUS PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    
    // Get file name information
    Status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo
    );
    
    if (NT_SUCCESS(Status)) {
        FltParseFileNameInformation(NameInfo);
        
        // Check if this is a protected path
        if (IsPathProtected(&NameInfo->Name)) {
            // BLOCK: Deny access with STATUS_ACCESS_DENIED
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            
            // Log blocked operation
            DbgPrint("[AntiRansomware] BLOCKED FILE ACCESS: %wZ\n", &NameInfo->Name);
            
            FltReleaseFileNameInformation(NameInfo);
            return FLT_PREOP_COMPLETE;
        }
        
        FltReleaseFileNameInformation(NameInfo);
    }
    
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// Post-Create callback: Log successful file opens
FLT_POSTOP_CALLBACK_STATUS PostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(Data);
    
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// Pre-Write callback: Block writes to protected files
FLT_PREOP_CALLBACK_STATUS PreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    
    // Get file name information
    Status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo
    );
    
    if (NT_SUCCESS(Status)) {
        FltParseFileNameInformation(NameInfo);
        
        // Check if this is a protected path
        if (IsPathProtected(&NameInfo->Name)) {
            // BLOCK: Deny write access
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            
            DbgPrint("[AntiRansomware] BLOCKED FILE WRITE: %wZ\n", &NameInfo->Name);
            
            FltReleaseFileNameInformation(NameInfo);
            return FLT_PREOP_COMPLETE;
        }
        
        FltReleaseFileNameInformation(NameInfo);
    }
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Pre-SetInformation callback: Block file deletion/rename on protected paths
FLT_PREOP_CALLBACK_STATUS PreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    
    // Get file name information
    Status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &NameInfo
    );
    
    if (NT_SUCCESS(Status)) {
        FltParseFileNameInformation(NameInfo);
        
        // Check if this is a protected path
        if (IsPathProtected(&NameInfo->Name)) {
            // Block delete and rename operations
            if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation ||
                Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformationEx ||
                Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
                Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx) {
                
                // BLOCK: Deny operation
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                
                DbgPrint("[AntiRansomware] BLOCKED FILE MODIFICATION: %wZ\n", &NameInfo->Name);
                
                FltReleaseFileNameInformation(NameInfo);
                return FLT_PREOP_COMPLETE;
            }
        }
        
        FltReleaseFileNameInformation(NameInfo);
    }
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Driver Entry Point
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    
    NTSTATUS Status = STATUS_SUCCESS;
    
    // Register filter with filter manager
    Status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    
    // Start filtering
    Status = FltStartFiltering(gFilterHandle);
    
    if (!NT_SUCCESS(Status)) {
        FltUnregisterFilter(gFilterHandle);
        return Status;
    }
    
    return STATUS_SUCCESS;
}

// Driver Unload Routine
NTSTATUS FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    
    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
    
    return STATUS_SUCCESS;
}
