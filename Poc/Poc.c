/*++

Module Name:

    Poc.c

Abstract:

    This is the main module of the Poc miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include "global.h"
#include "utils.h"
#include "context.h"
#include "filefuncs.h"
#include "cipher.h"
#include "fileobject.h"
#include "write.h"
#include "read.h"
#include "fileinfo.h"
#include "commport.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
PocInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
PocInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
PocInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );


NTSTATUS
PocUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
PocInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
PocPreCreateOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
PocPostCreateOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
PocPreCleanupOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
PocPostCleanupOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
PocPreCloseOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
PocPostCloseOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, PocUnload)
#pragma alloc_text(PAGE, PocInstanceQueryTeardown)
#pragma alloc_text(PAGE, PocInstanceSetup)
#pragma alloc_text(PAGE, PocInstanceTeardownStart)
#pragma alloc_text(PAGE, PocInstanceTeardownComplete)
#pragma alloc_text(PAGE, PocPostCreateOperation)
#pragma alloc_text(PAGE, PocPostCloseOperation)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_CLOSE,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_READ,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_WRITE,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_SET_EA,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      PocPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_PNP,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      PocPreOperation,
      PocPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      PocPreOperation,
      PocPostOperation },

#endif // TODO

    { IRP_MJ_CREATE,
      0,
      PocPreCreateOperation,
      PocPostCreateOperation },

    { IRP_MJ_READ,
      0,
      PocPreReadOperation,
      PocPostReadOperation },

    { IRP_MJ_WRITE,
      0,
      PocPreWriteOperation,
      PocPostWriteOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      PocPreQueryInformationOperation,
      PocPostQueryInformationOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      PocPreSetInformationOperation,
      PocPostSetInformationOperation },

    { IRP_MJ_CLEANUP,
      0,
      PocPreCleanupOperation,
      PocPostCleanupOperation },

    { IRP_MJ_CLOSE,
      0,
      PocPreCloseOperation,
      PocPostCloseOperation },

    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

    { FLT_STREAM_CONTEXT,
      0,
      PocContextCleanup,
      POC_STREAM_CONTEXT_SIZE,
      POC_STREAM_CONTEXT_TAG },

    { FLT_STREAMHANDLE_CONTEXT,
      0,
      PocContextCleanup,
      POC_STREAMHANDLE_CONTEXT_SIZE,
      POC_STREAMHANDLE_CONTEXT_TAG },

    { FLT_VOLUME_CONTEXT,
      0,
      PocContextCleanup,
      POC_VOLUME_CONTEXT_SIZE,
      POC_VOLUME_CONTEXT_TAG },

    { FLT_CONTEXT_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    ContextRegistration,                //  Context
    Callbacks,                          //  Operation callbacks

    PocUnload,                           //  MiniFilterUnload

    PocInstanceSetup,                    //  InstanceSetup
    PocInstanceQueryTeardown,            //  InstanceQueryTeardown
    PocInstanceTeardownStart,            //  InstanceTeardownStart
    PocInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
PocInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PPOC_VOLUME_CONTEXT ctx = NULL;
    NTSTATUS status = STATUS_SUCCESS;


    try {

        //
        //  Allocate a volume context structure.
        //

        status = FltAllocateContext(FltObjects->Filter,
            FLT_VOLUME_CONTEXT,
            sizeof(POC_VOLUME_CONTEXT),
            NonPagedPool,
            &ctx);

        if (!NT_SUCCESS(status)) {

            //
            //  We could not allocate a context, quit now
            //

            leave;
        }

        //
        //  Always get the volume properties, so I can get a sector size
        //

        ctx->SectorSize = PocQueryVolumeSectorSize(FltObjects->Volume);

        //
        //  Save the sector size in the context for later use.  Note that
        //  we will pick a minimum sector size if a sector size is not
        //  specified.
        //

        if (0 == ctx->SectorSize)
        {
            DbgPrint("PocInstanceSetup->PocQueryVolumeSectorSize failed.\n");
            leave;
        }
       

        status = FltSetVolumeContext(FltObjects->Volume,
            FLT_SET_CONTEXT_KEEP_IF_EXISTS,
            ctx,
            NULL);

       
        //
        //  It is OK for the context to already be defined.
        //

        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

            status = STATUS_SUCCESS;
        }

    }
    finally {

        //
        //  Always release the context.  If the set failed, it will free the
        //  context.  If not, it will remove the reference added by the set.
        //  Note that the name buffer in the ctx will get freed by the context
        //  cleanup routine.
        //

        if (ctx) {

            FltReleaseContext(ctx);
        }

       
    }

    return status;

}


NTSTATUS
PocInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Poc!PocInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
PocInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Poc!PocInstanceTeardownStart: Entered\n") );
}


VOID
PocInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Poc!PocInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Poc!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }

        status = PocInitCommPort();

        if (STATUS_SUCCESS != status)
        {
            DbgPrint("DriverEntry->PocInitCommPort failed. Status = 0x%x.\n", status);
            FltUnregisterFilter(gFilterHandle);
        }

        status = PocInitAesECBKey();

        if (STATUS_SUCCESS != status)
        {
            DbgPrint("DriverEntry->PocInitAesKey failed. Status = 0x%x.\n", status);
            PocCloseCommPort();
            FltUnregisterFilter(gFilterHandle);
        }

        RtlMoveMemory(EncryptionTailer.Flag, POC_ENCRYPTION_HEADER_FLAG, strlen(POC_ENCRYPTION_HEADER_FLAG));

        RtlMoveMemory(
            EncryptionTailer.EncryptionAlgorithmType,
            POC_ENCRYPTION_HEADER_EA_TYPE, 
            strlen(POC_ENCRYPTION_HEADER_EA_TYPE));


    }

    return status;
}

NTSTATUS
PocUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Poc!PocUnload: Entered\n") );

    PocCloseCommPort();

    PocAesCleanup();

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
PocPreCreateOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    NTSTATUS Status;

    WCHAR FileExtension[POC_MAX_NAME_LENGTH] = { 0 };
    WCHAR FileName[POC_MAX_NAME_LENGTH] = { 0 };

    
    Status = PocGetFileNameOrExtension(Data, FileExtension, FileName);

    if (STATUS_SUCCESS != Status)
    {
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto EXIT;
    }

    Status = PocBypassIrrelevantFileExtension(FileExtension);

    if (POC_IRRELEVENT_FILE_EXTENSION == Status)
    {
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto EXIT;
    }

    Status = PocBypassIrrelevantPath(FileName);

    if (POC_IS_IRRELEVENT_PATH == Status)
    {
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto EXIT;
    }

    Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;

EXIT:

    return Status;
}


FLT_POSTOP_CALLBACK_STATUS
PocPostCreateOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    NTSTATUS Status;

    PPOC_STREAM_CONTEXT StreamContext = NULL;
    BOOLEAN ContextCreated = FALSE;


    CHAR ProcessName[POC_MAX_NAME_LENGTH] = { 0 };
    WCHAR FileName[POC_MAX_NAME_LENGTH] = { 0 };

    Status = PocGetProcessName(Data, ProcessName);

    //如果FO创建失败，不进入PocFindOrCreateStreamContext
    if (STATUS_SUCCESS != Data->IoStatus.Status)
    {
        Status = FLT_POSTOP_FINISHED_PROCESSING;
        goto EXIT;
    }

    Status = PocBypassIrrelevantProcess(ProcessName);

    if (POC_IS_IRRELEVENT_PROCESS == Status)
    {
        Status = FLT_POSTOP_FINISHED_PROCESSING;
        goto EXIT;
    }

    Status = PocFindOrCreateStreamContext(
        Data->Iopb->TargetInstance, 
        Data->Iopb->TargetFileObject, 
        TRUE, 
        &StreamContext, 
        &ContextCreated);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocPostCreateOperation->CtxFindOrCreateStreamContext failed. Status = 0x%x ProcessName = %s\n", 
            Status, ProcessName);
        Status = FLT_POSTOP_FINISHED_PROCESSING;
        goto EXIT;
    }


    if (ContextCreated)
    {
        Status = PocGetFileNameOrExtension(Data, NULL, FileName);

        if (STATUS_SUCCESS != Status)
        {
            DbgPrint("PocPostCreateOperation->PocGetFileNameOrExtension failed. Status = 0x%x ProcessName = %s\n",
                Status, ProcessName);
            Status = FLT_POSTOP_FINISHED_PROCESSING;
            goto EXIT;
        }

        DbgPrint("PocPostCreateOperation->ContextCreated Fcb = %p FileName = %ws ProcessName = %s.\n", 
            FltObjects->FileObject->FsContext,
            FileName,
            ProcessName);


        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

        RtlZeroMemory(StreamContext->FileName, POC_MAX_NAME_LENGTH);

        if(wcslen(FileName) < POC_MAX_NAME_LENGTH)
            RtlMoveMemory(StreamContext->FileName, FileName, wcslen(FileName) * sizeof(WCHAR));

        ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);
        
    }

    //DbgPrint("\nPocPostCreateOperation->enter ProcessName = %s FileName = %ws.\n", ProcessName, FileName);


    if (FALSE == StreamContext->IsCipherText)
    {
        Status = PocCreateFileForEncTailer(FltObjects, StreamContext, ProcessName);

        if (POC_FILE_HAS_ENCRYPTION_TAILER == Status ||
            POC_TAILER_WRONG_FILE_NAME == Status)
        {
            PocUpdateFlagInStreamContext(StreamContext, Status);
        }
        else
        {
            Status = FLT_POSTOP_FINISHED_PROCESSING;
            goto EXIT;
        }
    }

    

    /*
    * 密文缓冲建立，如果已经有了，就直接用
    * 应该以DataSectionObject是否创建为准
    */

    Status = PocIsUnauthorizedProcess(ProcessName);

    if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, 
        (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA)) &&
        POC_IS_UNAUTHORIZED_PROCESS == Status)
    {

        DbgPrint("\nPocPostCreateOperation->SectionObjectPointers operation enter Process = %s.\n", ProcessName);

        if (NULL == StreamContext->ShadowSectionObjectPointers->DataSectionObject)
        {
            Status = PocInitShadowSectionObjectPointers(FltObjects, StreamContext);

            if (STATUS_SUCCESS != Status)
            {
                DbgPrint("PocPostCreateOperation->PocInitShadowSectionObjectPointers failed. Status = 0x%x\n", Status);
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                goto EXIT;
            }

        }
        else
        {
            
            Status = PocChangeSectionObjectPointerSafe(
                FltObjects->FileObject,
                StreamContext->ShadowSectionObjectPointers);

            if (STATUS_SUCCESS != Status)
            {
                DbgPrint("PocPostCreateOperation->PocChangeSectionObjectPointerSafe failed.\n");
                DbgBreakPoint();
            }

            DbgPrint("PocPostCreateOperation->%ws already has ciphertext cache map. Change FO->SOP to chiphertext SOP.\n",
                StreamContext->FileName);
        }

        if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
            (FILE_READ_DATA)))
        {
            Status = PocFlushOriginalCache(
                FltObjects,
                StreamContext->FileName);

            if (STATUS_SUCCESS != Status)
            {
                DbgPrint("PocPostCreateOperation->PocFlushOriginalCache failed. Status = 0x%x\n", Status);
            }
            else
            {
                DbgPrint("\nPocPostCreateOperation->PocFlushOriginalCache %ws success.\n", StreamContext->FileName);
            }
        }


        DbgPrint("\n");
        
    }


    Status = FLT_POSTOP_FINISHED_PROCESSING;

EXIT:

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return Status;
}


FLT_PREOP_CALLBACK_STATUS
PocPreCleanupOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    NTSTATUS Status; 

    PPOC_STREAM_CONTEXT StreamContext = NULL;
    BOOLEAN ContextCreated = FALSE;

    CHAR ProcessName[POC_MAX_NAME_LENGTH] = { 0 };

    Status = PocGetProcessName(Data, ProcessName);

    Status = PocFindOrCreateStreamContext(
        Data->Iopb->TargetInstance,
        Data->Iopb->TargetFileObject,
        FALSE,
        &StreamContext,
        &ContextCreated);

    if (STATUS_SUCCESS != Status)
    {
        if (STATUS_NOT_FOUND != Status)      //说明不是目标扩展文件，在Create中没有创建StreamContext，不认为是个错误
            DbgPrint("PocPreCleanupOperation->PocFindOrCreateStreamContext failed. Status = 0x%x\n", Status);
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto EXIT;
    }
    

    /*DbgPrint("\nPocPreCleanupOperation->enter ProcessName = %s File = %ws StreamContext->Flag = 0x%x.\n",
        ProcessName, StreamContext->FileName, StreamContext->Flag);*/


    Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;

EXIT:

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return Status;
}


FLT_POSTOP_CALLBACK_STATUS
PocPostCleanupOperation(
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
PocPreCloseOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    NTSTATUS Status;

    PPOC_STREAM_CONTEXT StreamContext = NULL;
    BOOLEAN ContextCreated = FALSE;

    CHAR ProcessName[POC_MAX_NAME_LENGTH] = { 0 };

    Status = PocGetProcessName(Data, ProcessName);

    Status = PocFindOrCreateStreamContext(
        Data->Iopb->TargetInstance, 
        Data->Iopb->TargetFileObject, 
        FALSE, 
        &StreamContext, 
        &ContextCreated);

    if (STATUS_SUCCESS != Status)
    {
        if (STATUS_NOT_FOUND != Status)      //说明不是目标扩展文件，在Create中没有创建StreamContext，不认为是个错误
            DbgPrint("PocPreCloseOperation->PocFindOrCreateStreamContext failed. Status = 0x%x\n", Status);
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto EXIT;
    }


    /*DbgPrint("\nPocPreCloseOperation->enter ProcessName = %s File = %ws StreamContext->Flag = 0x%x.\n",
        ProcessName, StreamContext->FileName, StreamContext->Flag);*/


    /*
    * Close意味着CM和MM已经处理完毕，FO的引用清零，
    * 其实SOP换不换回来无所谓，为了严谨一些，还是换回来吧
    */
    if (FltObjects->FileObject->SectionObjectPointer == StreamContext->ShadowSectionObjectPointers)
    {

        Status = PocChangeSectionObjectPointerSafe(
            FltObjects->FileObject,
            StreamContext->OriginSectionObjectPointers);


        DbgPrint("PocPreCloseOperation->Change SOP success ProcessName = %s File = %ws.\n", 
            ProcessName, StreamContext->FileName);
    }



    *CompletionContext = StreamContext;
    Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    return Status;

EXIT:

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return Status;
}


FLT_POSTOP_CALLBACK_STATUS
PocPostCloseOperation(
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

    PAGED_CODE();

    ASSERT(CompletionContext != NULL);

    NTSTATUS Status = 0;
    PPOC_STREAM_CONTEXT StreamContext = NULL;

    StreamContext = CompletionContext;


    if (POC_TO_APPEND_ENCRYPTION_TAILER == StreamContext->Flag || 
        POC_TAILER_WRONG_FILE_NAME == StreamContext->Flag)
    {
        PocUpdateFlagInStreamContext(StreamContext, POC_BEING_APPEND_ENC_TAILER);

        Status = PocAppendEncTailerToFile(FltObjects, StreamContext);

        if (STATUS_SUCCESS != Status)
        {
            PocUpdateFlagInStreamContext(StreamContext, POC_TO_APPEND_ENCRYPTION_TAILER);
            DbgPrint("PocPostCloseOperation->PocAppendEncTailerToFile failed. Status = 0x%x. Try again.\n", Status);
            Status = FLT_POSTOP_FINISHED_PROCESSING;
            goto EXIT;
        }

        DbgPrint("\nPocPostCloseOperation->Append tailer success. FileName = %ws.\n\n", 
            StreamContext->FileName);

        PocUpdateFlagInStreamContext(StreamContext, POC_FILE_HAS_ENCRYPTION_TAILER);

    }
    else if (POC_RENAME_TO_ENCRYPT == StreamContext->Flag)
    {
        PocUpdateFlagInStreamContext(StreamContext, POC_BEING_DIRECT_ENCRYPTING);

        Status = PocReentryToEncrypt(FltObjects->Instance, StreamContext->FileName);

        if (STATUS_SUCCESS != Status)
        {
            PocUpdateFlagInStreamContext(StreamContext, POC_RENAME_TO_ENCRYPT);
            DbgPrint("PocPostCloseOperation->PocReentryToEncrypt failed. Status = 0x%x. Try again.\n", Status);
            Status = FLT_POSTOP_FINISHED_PROCESSING;
            goto EXIT;
        }

        DbgPrint("\nPocPostCloseOperation->PocReentryToEncrypt success. FileName = %ws.\n\n", 
            StreamContext->FileName);
    }


EXIT:

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}
