
#include "global.h"
#include "context.h"
#include "fileobject.h"
#include "cipher.h"
#include "import.h"
#include "utils.h"


NTSTATUS
PocCreateStreamContext(
    _In_ PFLT_FILTER FilterHandle,
    _Outptr_ PPOC_STREAM_CONTEXT* StreamContext
)
/*++

Routine Description:

    This routine creates a new stream context

Arguments:

    StreamContext         - Returns the stream context

Return Value:

    Status

--*/
{
    NTSTATUS status;
    PPOC_STREAM_CONTEXT streamContext = NULL;

    PAGED_CODE();
    //
    //  Allocate a stream context
    //

    //PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("[PocCreateStreamContext]: Allocating stream context \n"));

    status = FltAllocateContext(FilterHandle,
        FLT_STREAM_CONTEXT,
        POC_STREAM_CONTEXT_SIZE,
        NonPagedPool,
        &streamContext);

    if (!NT_SUCCESS(status)) {

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("[PocCreateStreamContext]: Failed to allocate stream context with status 0x%x \n",
            status));
        return status;
    }

    RtlZeroMemory(streamContext, POC_STREAM_CONTEXT_SIZE);


    streamContext->FileName = ExAllocatePoolWithTag(NonPagedPool, POC_MAX_NAME_LENGTH * sizeof(WCHAR), POC_STREAM_CONTEXT_TAG);

    if (streamContext->FileName == NULL)
    {
        FltReleaseContext(streamContext);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(streamContext->FileName, POC_MAX_NAME_LENGTH * sizeof(WCHAR));


    streamContext->ShadowSectionObjectPointers = ExAllocatePoolWithTag(NonPagedPool,
        PAGE_SIZE,
        POC_STREAM_CONTEXT_TAG);

    if (streamContext->ShadowSectionObjectPointers == NULL)
    {
        FltReleaseContext(streamContext);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(streamContext->ShadowSectionObjectPointers, PAGE_SIZE);


    streamContext->PageNextToLastForWrite.Buffer= ExAllocatePoolWithTag(NonPagedPool,
        PAGE_SIZE + AES_BLOCK_SIZE,
        POC_STREAM_CONTEXT_TAG);

    if (streamContext->PageNextToLastForWrite.Buffer == NULL)
    {
        FltReleaseContext(streamContext);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(streamContext->PageNextToLastForWrite.Buffer, PAGE_SIZE + AES_BLOCK_SIZE);


    streamContext->Resource = ExAllocatePoolWithTag(NonPagedPool,
        sizeof(ERESOURCE),
        POC_RESOURCE_TAG);

    if (streamContext->Resource == NULL) {

        FltReleaseContext(streamContext);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExInitializeResourceLite(streamContext->Resource);


    *StreamContext = streamContext;

    return STATUS_SUCCESS;
}


NTSTATUS
PocFindOrCreateStreamContext(
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN CreateIfNotFound,
    OUT PPOC_STREAM_CONTEXT* StreamContext,
    OUT PBOOLEAN ContextCreated
)
/*++

Routine Description:

    This routine finds the stream context for the target stream.
    Optionally, if the context does not exist this routing creates
    a new one and attaches the context to the stream.

Arguments:

    Cbd                   - Supplies a pointer to the callbackData which
                            declares the requested operation.
    CreateIfNotFound      - Supplies if the stream must be created if missing
    StreamContext         - Returns the stream context
    ContextCreated        - Returns if a new context was created

Return Value:

    Status

--*/
{
    NTSTATUS status;
    PPOC_STREAM_CONTEXT streamContext;
    PPOC_STREAM_CONTEXT oldStreamContext;

    PAGED_CODE();

    *StreamContext = NULL;
    if (ContextCreated != NULL) *ContextCreated = FALSE;

    //
    //  First try to get the stream context.
    //

    /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("[Ctx]: Trying to get stream context (FileObject = %p, Instance = %p)\n",
            Cbd->Iopb->TargetFileObject,
            Cbd->Iopb->TargetInstance));*/

    status = FltGetStreamContext(Instance,
        FileObject,
        &streamContext);
    
    //
    //  If the call failed because the context does not exist
    //  and the user wants to creat a new one, the create a
    //  new context
    //

    if (!NT_SUCCESS(status) &&
        (status == STATUS_NOT_FOUND) &&
        CreateIfNotFound) {


        //
        //  Create a stream context
        //

        /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("[PocFindOrCreateStreamContext]: Creating stream context (FileObject = %p, Instance = %p)\n",
                Cbd->Iopb->TargetFileObject,
                Cbd->Iopb->TargetInstance));*/

        status = PocCreateStreamContext(gFilterHandle , &streamContext);

        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("[Ctx]: Failed to create stream context with status 0x%x. (FileObject = %p, Instance = %p)\n",
                    status,
                    FileObject,
                    Instance));

            return status;
        }


        //
        //  Set the new context we just allocated on the file object
        //

        /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("[PocFindOrCreateStreamContext]: Setting stream context %p (FileObject = %p, Instance = %p)\n",
                streamContext,
                Cbd->Iopb->TargetFileObject,
                Cbd->Iopb->TargetInstance));*/

        status = FltSetStreamContext(Instance,
            FileObject,
            FLT_SET_CONTEXT_KEEP_IF_EXISTS,
            streamContext,
            &oldStreamContext);

        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("[PocFindOrCreateStreamContext]: Failed to set stream context with status 0x%x. (FileObject = %p, Instance = %p)\n",
                    status,
                    FileObject,
                    Instance));
            //
            //  We release the context here because FltSetStreamContext failed
            //
            //  If FltSetStreamContext succeeded then the context will be returned
            //  to the caller. The caller will use the context and then release it
            //  when he is done with the context.
            //

            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("[PocFindOrCreateStreamContext]: Releasing stream context %p (FileObject = %p, Instance = %p)\n",
                    streamContext,
                    FileObject,
                    Instance));

            FltReleaseContext(streamContext);

            if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

                //
                //  FltSetStreamContext failed for a reason other than the context already
                //  existing on the stream. So the object now does not have any context set
                //  on it. So we return failure to the caller.
                //

                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("[PocFindOrCreateStreamContext]: Failed to set stream context with status 0x%x != STATUS_FLT_CONTEXT_ALREADY_DEFINED. (FileObject = %p, Instance = %p)\n",
                        status,
                        FileObject,
                        Instance));

                return status;
            }

            //
            //  Race condition. Someone has set a context after we queried it.
            //  Use the already set context instead
            //

            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("[PocFindOrCreateStreamContext]: Stream context already defined. Retaining old stream context %p (FileObject = %p, Instance = %p)\n",
                    oldStreamContext,
                    FileObject,
                    Instance));

            //
            //  Return the existing context. Note that the new context that we allocated has already been
            //  realeased above.
            //

            streamContext = oldStreamContext;
            status = STATUS_SUCCESS;

        }
        else {

            if (ContextCreated != NULL) *ContextCreated = TRUE;
        }
    }


    *StreamContext = streamContext;

    return status;
}


VOID
PocContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
)
{

    PPOC_STREAM_CONTEXT streamContext;

    PAGED_CODE();

    switch (ContextType) {

    case FLT_STREAM_CONTEXT:
    {
        streamContext = (PPOC_STREAM_CONTEXT)Context;

        //
        //  Delete the resource and memory the memory allocated for the resource
        //

        PocCleanupSectionObjectPointers(
            streamContext);


        if (streamContext->FileName != NULL)
        {
            ExFreePoolWithTag(streamContext->FileName, POC_STREAM_CONTEXT_TAG);
            streamContext->FileName = NULL;
        }

        if (streamContext->PageNextToLastForWrite.Buffer != NULL)
        {
            ExFreePoolWithTag(streamContext->PageNextToLastForWrite.Buffer, POC_STREAM_CONTEXT_TAG);
            streamContext->PageNextToLastForWrite.Buffer = NULL;
        }

        if (NULL != streamContext->FlushFileObject)
        {
            ObDereferenceObject(streamContext->FlushFileObject);
            streamContext->FlushFileObject = NULL;
        }

        if (streamContext->Resource != NULL)
        {
            ExDeleteResourceLite(streamContext->Resource);
            ExFreePoolWithTag(streamContext->Resource, POC_RESOURCE_TAG);
            streamContext->Resource = NULL;
        }

        break;
    }
    case FLT_STREAMHANDLE_CONTEXT:
    {
        break;
    }
    case FLT_VOLUME_CONTEXT:
    {
        break;
    }

    }

}


NTSTATUS PocUpdateNameInStreamContext(
    IN PPOC_STREAM_CONTEXT StreamContext, 
    IN PWCHAR NewFileName)
{
    if (NULL == StreamContext)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocUpdateNameInStreamContext->StreamContext is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == NewFileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocUpdateNameInStreamContext->NewFileName is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

    RtlZeroMemory(StreamContext->FileName, POC_MAX_NAME_LENGTH * sizeof(WCHAR));
    RtlMoveMemory(StreamContext->FileName, NewFileName, wcslen(NewFileName) * sizeof(WCHAR));

    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);


    return STATUS_SUCCESS;
}


VOID PocUpdateFlagInStreamContext(
    IN PPOC_STREAM_CONTEXT StreamContext,
    IN ULONG Flag)
{
    if (NULL == StreamContext)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocUpdateFlagInStreamContext->StreamContext is NULL.\n"));
        return;
    }

    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

    StreamContext->Flag = Flag;

    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

}


NTSTATUS PocUpdateStreamContextProcessInfo(
    IN PFLT_CALLBACK_DATA Data,
    IN OUT PPOC_STREAM_CONTEXT StreamContext)
{
    if (NULL == StreamContext)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->StreamContext is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PEPROCESS eProcess = NULL;
    HANDLE ProcessId = NULL;

    PPOC_CREATED_PROCESS_INFO OutProcessInfo = NULL;

    ULONG Free = 0xFF;

    eProcess = FltGetRequestorProcess(Data);

    if (NULL == eProcess) {

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->EProcess FltGetRequestorProcess failed.\n", __FUNCTION__));
        Status = STATUS_UNSUCCESSFUL;
        goto EXIT;
    }

    if (_strnicmp((PCHAR)PsGetProcessImageFileName(eProcess), "explorer.exe", strlen("explorer.exe")) == 0 ||
        _strnicmp((PCHAR)PsGetProcessImageFileName(eProcess), "PocUserPanel.exe", strlen("PocUserPanel.exe")) == 0)
    {
        goto EXIT;
    }


    ProcessId = PsGetProcessId(eProcess);

    if (NULL == ProcessId)
    {
        /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
            ("%s->PsGetProcessId %p failed.\n",
                __FUNCTION__, eProcess));*/
        Status = STATUS_UNSUCCESSFUL;
        goto EXIT;
    }

    Status = PocFindProcessInfoNodeByPidEx(
        ProcessId,
        &OutProcessInfo,
        FALSE,
        FALSE);

    if (STATUS_SUCCESS != Status || 
        OutProcessInfo->OwnedProcessRule->Access != POC_PR_ACCESS_READWRITE)
    {
        goto EXIT;
    }

    Status = STATUS_UNSUCCESSFUL;


    for (ULONG i = 0; i < POC_MAX_AUTHORIZED_PROCESS_COUNT; i++)
    {

        if (NULL == StreamContext->ProcessId[i] && 0xFF == Free)
        {
            Free = i;
        }

        
        if (ProcessId == StreamContext->ProcessId[i])
        {
            Status = STATUS_SUCCESS;
            goto EXIT;
        }

    }

    if (STATUS_SUCCESS != Status)
    {
        StreamContext->ProcessId[Free] = ProcessId;

        Status = STATUS_SUCCESS;
    }

EXIT:

    return Status;
}


VOID PocInstanceSetupWhenSafe(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);


    ASSERT(NULL != Context);
    PFLT_VOLUME Volume = Context;

    PPOC_VOLUME_CONTEXT ctx = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    WCHAR Buffer[POC_MAX_NAME_LENGTH * 2] = { 0 };
    UNICODE_STRING VolumeName = { 0 };

    try {

        //
        //  Allocate a volume context structure.
        //

        status = FltAllocateContext(gFilterHandle,
            FLT_VOLUME_CONTEXT,
            sizeof(POC_VOLUME_CONTEXT),
            NonPagedPool,
            &ctx);

        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                ("%s->FltAllocateContext failed. Status = 0x%x.\n", __FUNCTION__, status));

            leave;
        }

        //
        //  Always get the volume properties, so I can get a sector size
        //

        ctx->SectorSize = PocQueryVolumeSectorSize(Volume);

        //
        //  Save the sector size in the context for later use.  Note that
        //  we will pick a minimum sector size if a sector size is not
        //  specified.
        //

        if (0 == ctx->SectorSize)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInstanceSetup->PocQueryVolumeSectorSize failed. SectorSize = %d\n",
                ctx->SectorSize));
            leave;
        }


        status = FltSetVolumeContext(Volume,
            FLT_SET_CONTEXT_KEEP_IF_EXISTS,
            ctx,
            NULL);


        //
        //  It is OK for the context to already be defined.
        //

        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

            status = STATUS_SUCCESS;
            leave;
        }
        else if (!NT_SUCCESS(status))
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                ("%s->FltSetVolumeContext failed. Status = 0x%x.\n", __FUNCTION__, status));

            leave;
        }


        RtlInitUnicodeString(&VolumeName, Buffer);
        VolumeName.MaximumLength = sizeof(Buffer);

        status = FltGetVolumeName(Volume, &VolumeName, NULL);

        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                ("%s->FltGetVolumeName failed. Status = 0x%x.\n", __FUNCTION__, status));
        }

        /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
            ("%s->Attach to volume = %p name = %ws success.\n",
                __FUNCTION__,
                Volume, VolumeName.Buffer));*/

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

    return;
}
