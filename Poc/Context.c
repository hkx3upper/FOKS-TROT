
#include "global.h"
#include "context.h"
#include "fileobject.h"
#include "cipher.h"


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


    streamContext->FileName = ExAllocatePoolWithTag(NonPagedPool, POC_MAX_NAME_LENGTH, POC_STREAM_CONTEXT_TAG);

    if (streamContext->FileName == NULL)
    {
        FltReleaseContext(streamContext);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(streamContext->FileName, POC_MAX_NAME_LENGTH);


    streamContext->ShadowSectionObjectPointers = ExAllocatePoolWithTag(NonPagedPool,
        sizeof(SECTION_OBJECT_POINTERS),
        POC_STREAM_CONTEXT_TAG);

    if (streamContext->ShadowSectionObjectPointers == NULL)
    {
        FltReleaseContext(streamContext);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(streamContext->ShadowSectionObjectPointers, sizeof(SECTION_OBJECT_POINTERS));


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
    _In_ BOOLEAN CreateIfNotFound,
    _Outptr_ PPOC_STREAM_CONTEXT* StreamContext,
    _Out_opt_ PBOOLEAN ContextCreated
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


NTSTATUS
PocCreateStreamHandleContext(
    _Outptr_ PPOC_STREAMHANDLE_CONTEXT* StreamHandleContext
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
    PPOC_STREAMHANDLE_CONTEXT streamHandleContext;

    PAGED_CODE();

    //
    //  Allocate a stream context
    //


    status = FltAllocateContext(gFilterHandle,
        FLT_STREAMHANDLE_CONTEXT,
        POC_STREAMHANDLE_CONTEXT_SIZE,
        PagedPool,
        &streamHandleContext);

    if (!NT_SUCCESS(status)) {

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateStreamHandleContext->Failed to allocate stream handle context with status 0x%x \n",
            status));

        return status;
    }

    //
    //  Initialize the newly created context
    //

    RtlZeroMemory(streamHandleContext, POC_STREAMHANDLE_CONTEXT_SIZE);


    *StreamHandleContext = streamHandleContext;

    return STATUS_SUCCESS;
}


NTSTATUS
PocCreateOrReplaceStreamHandleContext(
    _In_ PFLT_CALLBACK_DATA Cbd,
    _In_ BOOLEAN ReplaceIfExists,
    _Outptr_ PPOC_STREAMHANDLE_CONTEXT* StreamHandleContext,
    _Out_opt_ PBOOLEAN ContextReplaced
)
/*++

Routine Description:

    This routine creates a stream handle context for the target stream
    handle. Optionally, if the context already exists, this routine
    replaces it with the new context and releases the old context

Arguments:

    Cbd                   - Supplies a pointer to the callbackData which
                            declares the requested operation.
    ReplaceIfExists       - Supplies if the stream handle context must be
                            replaced if already present
    StreamContext         - Returns the stream context
    ContextReplaced       - Returns if an existing context was replaced

Return Value:

    Status

--*/
{
    NTSTATUS status;
    PPOC_STREAMHANDLE_CONTEXT streamHandleContext = NULL;
    PPOC_STREAMHANDLE_CONTEXT oldStreamHandleContext = NULL;

    PAGED_CODE();

    *StreamHandleContext = NULL;
    if (ContextReplaced != NULL) *ContextReplaced = FALSE;

    //
    //  Create a stream context
    //

    /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateOrReplaceStreamHandleContext->Creating stream handle context (FileObject = %p, Instance = %p)\n",
            Cbd->Iopb->TargetFileObject,
            Cbd->Iopb->TargetInstance));*/

    status = PocCreateStreamHandleContext(&streamHandleContext);

    if (!NT_SUCCESS(status)) {

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateOrReplaceStreamHandleContext->Failed to create stream context with status 0x%x. (FileObject = %p, Instance = %p)\n",
                status,
                Cbd->Iopb->TargetFileObject,
                Cbd->Iopb->TargetInstance));

        return status;
    }

    //
    //  Set the new context we just allocated on the file object
    //

    /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("[Ctx]: Setting stream context %p (FileObject = %p, Instance = %p, ReplaceIfExists = %x)\n",
            streamHandleContext,
            Cbd->Iopb->TargetFileObject,
            Cbd->Iopb->TargetInstance,
            ReplaceIfExists));*/

    status = FltSetStreamHandleContext(Cbd->Iopb->TargetInstance,
        Cbd->Iopb->TargetFileObject,
        ReplaceIfExists ? FLT_SET_CONTEXT_REPLACE_IF_EXISTS : FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        streamHandleContext,
        &oldStreamHandleContext);

    if (!NT_SUCCESS(status)) {

        /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateOrReplaceStreamHandleContext->Failed to set stream handle context with status 0x%x. (FileObject = %p, Instance = %p)\n",
                status,
                Cbd->Iopb->TargetFileObject,
                Cbd->Iopb->TargetInstance));*/

        //
        //  We release the context here because FltSetStreamContext failed
        //
        //  If FltSetStreamContext succeeded then the context will be returned
        //  to the caller. The caller will use the context and then release it
        //  when he is done with the context.
        //

        /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateOrReplaceStreamHandleContext->Releasing stream handle context %p (FileObject = %p, Instance = %p)\n",
                streamHandleContext,
                Cbd->Iopb->TargetFileObject,
                Cbd->Iopb->TargetInstance));*/

        FltReleaseContext(streamHandleContext);

        if (status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

            //
            //  FltSetStreamContext failed for a reason other than the context already
            //  existing on the stream. So the object now does not have any context set
            //  on it. So we return failure to the caller.
            //

            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateOrReplaceStreamHandleContext->Failed to set stream context with status 0x%x != STATUS_FLT_CONTEXT_ALREADY_DEFINED. (FileObject = %p, Instance = %p)\n",
                    status,
                    Cbd->Iopb->TargetFileObject,
                    Cbd->Iopb->TargetInstance));

            return status;
        }

        //
        //  We will reach here only if we have failed with STATUS_FLT_CONTEXT_ALREADY_DEFINED
        //  and we can fail with that code only if the context already exists and we have used
        //  the FLT_SET_CONTEXT_KEEP_IF_EXISTS flag

        FLT_ASSERT(ReplaceIfExists == FALSE);

        //
        //  Race condition. Someone has set a context after we queried it.
        //  Use the already set context instead
        //

        /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateOrReplaceStreamHandleContext->Stream context already defined. Retaining old stream context %p (FileObject = %p, Instance = %p)\n",
                oldStreamHandleContext,
                Cbd->Iopb->TargetFileObject,
                Cbd->Iopb->TargetInstance));*/

        //
        //  Return the existing context. Note that the new context that we allocated has already been
        //  realeased above.
        //

        streamHandleContext = oldStreamHandleContext;
        status = STATUS_SUCCESS;

    }
    else {

        //
        //  FltSetStreamContext has suceeded. The new context will be returned
        //  to the caller. The caller will use the context and then release it
        //  when he is done with the context.
        //
        //  However, if we have replaced an existing context then we need to
        //  release the old context so as to decrement the ref count on it.
        //
        //  Note that the memory allocated to the objects within the context
        //  will be freed in the context cleanup and must not be done here.
        //

        if (ReplaceIfExists &&
            oldStreamHandleContext != NULL) {

            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateOrReplaceStreamHandleContext->Releasing old stream handle context %p (FileObject = %p, Instance = %p)\n",
                    oldStreamHandleContext,
                    Cbd->Iopb->TargetFileObject,
                    Cbd->Iopb->TargetInstance));

            FltReleaseContext(oldStreamHandleContext);
            if (ContextReplaced != NULL) *ContextReplaced = TRUE;
        }
    }

    *StreamHandleContext = streamHandleContext;

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

    RtlZeroMemory(StreamContext->FileName, POC_MAX_NAME_LENGTH);
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
