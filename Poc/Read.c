
#include "read.h"
#include "context.h"
#include "utils.h"
#include "write.h"
#include "cipher.h"
#include "filefuncs.h"
#include "process.h"

FLT_POSTOP_CALLBACK_STATUS
PocPostReadOperationWhenSafe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

NTSTATUS PocPostReadDecrypt(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    IN PVOID OrigBuffer,
    IN PPOC_SWAP_BUFFER_CONTEXT* Context);


FLT_PREOP_CALLBACK_STATUS
PocPreReadOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    *CompletionContext = NULL;

    NTSTATUS Status = FLT_PREOP_SUCCESS_NO_CALLBACK;

    WCHAR ProcessName[POC_MAX_NAME_LENGTH] = { 0 };

    PPOC_STREAM_CONTEXT StreamContext = NULL;
    BOOLEAN ContextCreated = FALSE;

    BOOLEAN NonCachedIo = 0;

    LONGLONG StartingVbo = 0, ByteCount = 0;

    PCHAR NewBuffer = NULL;
    PMDL NewMdl = NULL;

    PPOC_SWAP_BUFFER_CONTEXT SwapBufferContext = NULL;
    ULONG Index = 0;

    StartingVbo = Data->Iopb->Parameters.Read.ByteOffset.QuadPart;
    ByteCount = Data->Iopb->Parameters.Read.Length;

    NonCachedIo = BooleanFlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE);

    if (0 == ByteCount)
    {
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto ERROR;
    }
    

    Status = PocFindOrCreateStreamContext(
        Data->Iopb->TargetInstance,
        Data->Iopb->TargetFileObject,
        FALSE,
        &StreamContext,
        &ContextCreated);

    if (STATUS_SUCCESS != Status)
    {
        if (STATUS_NOT_FOUND != Status && !FsRtlIsPagingFile(Data->Iopb->TargetFileObject))
            /*
            * 说明不是目标扩展文件，在Create中没有创建StreamContext，不认为是个错误
            * 或者是一个Paging file，这里会返回0xc00000bb，
            * 原因是Fcb->Header.Flags2, FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS被清掉了
            *
            //
            //  To make FAT match the present functionality of NTFS, disable
            //  stream contexts on paging files
            //

            if (IsPagingFile) {
                SetFlag( Fcb->Header.Flags2, FSRTL_FLAG2_IS_PAGING_FILE );
                ClearFlag( Fcb->Header.Flags2, FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS );
            }
            */
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocFindOrCreateStreamContext failed. Status = 0x%x.\n",
                __FUNCTION__,
                Status));
        }

        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto ERROR;
    }

    if (!StreamContext->IsCipherText)
    {
        // PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->leave. File is plaintext.\n", __FUNCTION__));
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto ERROR;
    }

    if (!FLT_IS_IRP_OPERATION(Data))
    {
        Status = FLT_PREOP_DISALLOW_FASTIO;
        goto ERROR;
    }

    Status = PocGetProcessName(Data, ProcessName);

    if (StartingVbo >= StreamContext->FileSize)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->%ws read end of file.\n", __FUNCTION__, ProcessName));
        Data->IoStatus.Status = STATUS_END_OF_FILE;
        Data->IoStatus.Information = 0;

        Status = FLT_PREOP_COMPLETE;
        goto ERROR;
    }



    if (!NonCachedIo && StartingVbo + ByteCount > StreamContext->FileSize)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->%ws cachedio read end of file Length = %d. NewLength = %I64d\n",
            __FUNCTION__,
            ProcessName,
            Data->Iopb->Parameters.Read.Length,
            StreamContext->FileSize - StartingVbo));
        Data->Iopb->Parameters.Read.Length = (ULONG)(StreamContext->FileSize - StartingVbo);
        FltSetCallbackDataDirty(Data);
    }


    SwapBufferContext = (PPOC_SWAP_BUFFER_CONTEXT)ExAllocatePoolWithTag(NonPagedPool,
        sizeof(POC_SWAP_BUFFER_CONTEXT),
        READ_BUFFER_TAG);

    if (NULL == SwapBufferContext)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag SwapBufferContext failed.\n", __FUNCTION__));
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        Status = FLT_PREOP_COMPLETE;
        goto ERROR;
    }

    RtlZeroMemory(SwapBufferContext, sizeof(POC_SWAP_BUFFER_CONTEXT));

    if (FltObjects->FileObject->SectionObjectPointer ==
        StreamContext->ShadowSectionObjectPointers)
    {
        SwapBufferContext->StreamContext = StreamContext;
        *CompletionContext = SwapBufferContext;
        Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
        goto EXIT;
    }


    if (NonCachedIo && StreamContext->IsCipherText)
    {
        NewBuffer = (PCHAR)FltAllocatePoolAlignedWithTag(FltObjects->Instance,
            NonPagedPool,
            ByteCount,
            READ_BUFFER_TAG);

        if (NULL == NewBuffer)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltAllocatePoolAlignedWithTag NewBuffer failed.\n", __FUNCTION__));
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            Status = FLT_PREOP_COMPLETE;
            goto ERROR;
        }

        RtlZeroMemory(NewBuffer, ByteCount);


        if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
        {

            NewMdl = IoAllocateMdl(NewBuffer, (ULONG)ByteCount, FALSE, FALSE, NULL);

            if (NewMdl == NULL)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->IoAllocateMdl NewMdl failed.\n", __FUNCTION__));
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                Status = FLT_PREOP_COMPLETE;
                goto ERROR;
            }

            MmBuildMdlForNonPagedPool(NewMdl);
        }


        /*
        * DbgPrint日志输出
        */
        RtlUnicodeToMultiByteN(
            SwapBufferContext->FileName,
            POC_MAX_NAME_LENGTH, 
            &Index, 
            StreamContext->FileName, 
            (ULONG)wcslen(StreamContext->FileName) * sizeof(WCHAR));

        SwapBufferContext->NewBuffer = NewBuffer;
        SwapBufferContext->NewMdl = NewMdl;
        SwapBufferContext->StreamContext = StreamContext;
        *CompletionContext = SwapBufferContext;

        Data->Iopb->Parameters.Read.ReadBuffer = NewBuffer;
        Data->Iopb->Parameters.Read.MdlAddress = NewMdl;
        FltSetCallbackDataDirty(Data);

        Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
        goto EXIT;
    }


    SwapBufferContext->StreamContext = StreamContext;
    *CompletionContext = SwapBufferContext;
    Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    goto EXIT;

ERROR:

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    if (NULL != SwapBufferContext)
    {
        ExFreePoolWithTag(SwapBufferContext, READ_BUFFER_TAG);
        SwapBufferContext = NULL;
    }

    if (NULL != NewBuffer)
    {
        FltFreePoolAlignedWithTag(FltObjects->Instance, NewBuffer, READ_BUFFER_TAG);
        NewBuffer = NULL;
    }

    if (NULL != NewMdl)
    {
        IoFreeMdl(NewMdl);
        NewMdl = NULL;
    }

EXIT:

    return Status;
}


FLT_POSTOP_CALLBACK_STATUS
PocPostReadOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
/*---------------------------------------------------------
函数名称:   PocPostReadOperation
函数描述:   Post Read的处理，主要包括数据的解密以及文件标识尾的隐藏
作者:       hkx3upper
更新维护:   wangzhankun
---------------------------------------------------------*/
/*
* https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_post_operation_callback
*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    ASSERT(CompletionContext != NULL);
    ASSERT(((PPOC_SWAP_BUFFER_CONTEXT)CompletionContext)->StreamContext != NULL);


    FLT_POSTOP_CALLBACK_STATUS Status = FLT_POSTOP_FINISHED_PROCESSING;
    PPOC_SWAP_BUFFER_CONTEXT SwapBufferContext = NULL;
    PPOC_STREAM_CONTEXT StreamContext = NULL;

    LONGLONG StartingVbo = 0, FileSize = 0;

    BOOLEAN NonCachedIo = FALSE;

    PVOID OrigBuffer = NULL;
    BOOLEAN CleanHere = TRUE;

    SwapBufferContext = CompletionContext;
    StreamContext = SwapBufferContext->StreamContext;

    StartingVbo = Data->Iopb->Parameters.Read.ByteOffset.QuadPart;
    FileSize = StreamContext->FileSize;

    NonCachedIo = BooleanFlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE);

    // 隐藏文件标识尾
    if (STATUS_SUCCESS == Data->IoStatus.Status)
    {
        if (StartingVbo + (LONGLONG)Data->IoStatus.Information > FileSize)
        {
            Data->IoStatus.Information = FileSize - StartingVbo;
        }
    }
    else if (!NT_SUCCESS(Data->IoStatus.Status) || (Data->IoStatus.Information == 0))
    {
        Status = FLT_POSTOP_FINISHED_PROCESSING;
        goto EXIT;
    }



    if (FltObjects->FileObject->SectionObjectPointer ==
        StreamContext->ShadowSectionObjectPointers)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Don't decrypt ciphertext cache map.\n", __FUNCTION__));
        Status = FLT_POSTOP_FINISHED_PROCESSING;
        goto EXIT;
    }



    if (NonCachedIo && StreamContext->IsCipherText)
    {

        if (Data->Iopb->Parameters.Read.MdlAddress != NULL)
        {

            FLT_ASSERT(((PMDL)Data->Iopb->Parameters.Read.MdlAddress)->Next == NULL);

            /*
            * https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmgetsystemaddressformdlsafe
            * This routine maps the physical pages that are described by the specified MDL into system address space,
            * if they are not already mapped to system address space.
            */
            OrigBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Read.MdlAddress,
                NormalPagePriority | MdlMappingNoExecute);

            if (OrigBuffer == NULL)
            {

                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Failed to get system address for MDL1: %p\n",
                    __FUNCTION__,
                    Data->Iopb->Parameters.Read.MdlAddress));

                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                goto EXIT;
            }
        }
        else if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ||
            FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION))
        {
            OrigBuffer = (PCHAR)Data->Iopb->Parameters.Read.ReadBuffer;
        }
        else
        {
            if (FltDoCompletionProcessingWhenSafe(Data,
                FltObjects,
                CompletionContext,
                Flags,
                PocPostReadOperationWhenSafe,
                &Status))
            {
                CleanHere = FALSE;
            }
            else
            {
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
            }

            goto EXIT;
        }


        PocPostReadDecrypt(Data, FltObjects, OrigBuffer, &SwapBufferContext);

    }

    Status = FLT_POSTOP_FINISHED_PROCESSING;

EXIT:

    if (CleanHere)
    {
        if (NULL != SwapBufferContext &&
            NULL != SwapBufferContext->NewBuffer)
        {
            FltFreePoolAlignedWithTag(
                FltObjects->Instance,
                SwapBufferContext->NewBuffer,
                READ_BUFFER_TAG);

            SwapBufferContext->NewBuffer = NULL;
        }

        if (NULL != SwapBufferContext)
        {
            ExFreePoolWithTag(SwapBufferContext, READ_BUFFER_TAG);
            SwapBufferContext = NULL;
        }

        if (StreamContext)
        {
            FltReleaseContext(StreamContext);
            StreamContext = NULL;
        }
    }

    return Status;
}


FLT_POSTOP_CALLBACK_STATUS
PocPostReadOperationWhenSafe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
/*---------------------------------------------------------
函数名称:   PocPostReadOperationWhenSafe
函数描述:   We had an arbitrary users buffer without a MDL
            so we needed to get to a safe IRQL so we could lock it and then copy the data.
作者:       wangzhankun
更新维护:
---------------------------------------------------------*/
{

    ASSERT(CompletionContext != NULL);

    PVOID OrigBuffer = NULL;
    NTSTATUS Status;

    PPOC_SWAP_BUFFER_CONTEXT SwapBufferContext = NULL;
    PPOC_STREAM_CONTEXT StreamContext = NULL;

    SwapBufferContext = CompletionContext;
    StreamContext = SwapBufferContext->StreamContext;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    FLT_ASSERT(Data->IoStatus.Information != 0);

    /*
    * https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltlockuserbuffer
    * <= APC_LEVEL
    * FltLockUserBuffer sets the MdlAddress (or OutputMdlAddress) member in the callback data
    * parameter structure (FLT_PARAMETERS) to point to the MDL for the locked pages.
    * If there is no MDL, FltLockUserBuffer allocates one.
    */

    Status = FltLockUserBuffer(Data); // 不需要使用者手动释放

    if (Status != STATUS_SUCCESS)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltLockUserBuffer failed. Status = 0x%x.\n", __FUNCTION__, Status));
        Data->IoStatus.Status = Status;
        Data->IoStatus.Information = 0;
        goto EXIT;
    }

    // Get a system address for the buffer
    OrigBuffer = MmGetSystemAddressForMdlSafe(
        Data->Iopb->Parameters.Read.MdlAddress,
        NormalPagePriority | MdlMappingNoExecute);

    if (OrigBuffer == NULL)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Failed to get system address for MDL1: %p\n",
            __FUNCTION__,
            Data->Iopb->Parameters.Read.MdlAddress));

        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;

        goto EXIT;
    }

    // Here will always have a system buffer address.
    PocPostReadDecrypt(Data, FltObjects, OrigBuffer, &SwapBufferContext);


EXIT:

    if (SwapBufferContext != NULL &&
        NULL != SwapBufferContext->NewBuffer)
    {
        FltFreePoolAlignedWithTag(FltObjects->Instance,
            SwapBufferContext->NewBuffer,
            READ_BUFFER_TAG);

        SwapBufferContext->NewBuffer = NULL;
    }

    if (NULL != SwapBufferContext)
    {
        ExFreePoolWithTag(SwapBufferContext, READ_BUFFER_TAG);
        SwapBufferContext = NULL;
    }

    if (StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}


NTSTATUS PocPostReadDecrypt(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    IN PVOID OrigBuffer,
    IN PPOC_SWAP_BUFFER_CONTEXT* Context)
/*
* 这个函数是有可能运行在DISPATCH_LEVEL上的，
* FltDoCompletionProcessingWhenSafe在PostRead有一定几率会返回失败，
* 所以并没有把PostRead整体放入FltDoCompletionProcessingWhenSafe中执行
*/
{

    NTSTATUS Status;

    ASSERT(Context);
    PPOC_SWAP_BUFFER_CONTEXT SwapBufferContext = *Context;
    ASSERT(SwapBufferContext);
    PPOC_STREAM_CONTEXT StreamContext = SwapBufferContext->StreamContext;
    ASSERT(StreamContext);

    LONGLONG StartingVbo = Data->Iopb->Parameters.Read.ByteOffset.QuadPart;

    /*
    * This is set to a request-dependent value.
    * For example, on successful completion of a transfer request,
    * this is set to the number of bytes transferred.
    * If a transfer request is completed with another STATUS_XXX,
    * this member is set to zero.
    */
    LONGLONG LengthReturned = Data->IoStatus.Information;
    LONGLONG FileSize = StreamContext->FileSize;

    LARGE_INTEGER ByteOffset = { 0 };
    ULONG ReadLength = 0;
    PCHAR outReadBuffer = NULL;
    ULONG BytesRead = 0;

    PCHAR TempNewBuffer = NULL;
    PCHAR TempOrigBuffer = NULL;

    PVOID NewBuffer = SwapBufferContext->NewBuffer;

    PPOC_VOLUME_CONTEXT VolumeContext = NULL;


    try
    {

        if (FileSize < AES_BLOCK_SIZE)
        {
            /*
            * 文件小于一个块
            */

            LengthReturned = AES_BLOCK_SIZE;

            Status = PocAesECBDecrypt(NewBuffer, (ULONG)LengthReturned, OrigBuffer, &(ULONG)LengthReturned);

            if (STATUS_SUCCESS != Status)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocAesECBDecrypt1 failed.\n", __FUNCTION__));
                Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                __leave;
            }
        }
        else if ((FileSize > StartingVbo + LengthReturned) &&
            (FileSize - (StartingVbo + LengthReturned) < AES_BLOCK_SIZE))
        {
            PAGED_CODE();
            /*
            * 当文件大于一个块，Cache Manager将数据分多次读入缓冲，或者其他以NonCachedIo形式
            * 最后一次读的数据小于一个块的情况下，现在在倒数第二个块做一下处理
            */

            ByteOffset.QuadPart = StartingVbo + LengthReturned;
            ReadLength = AES_BLOCK_SIZE;

            Status = PocReadFileNoCache(
                FltObjects->Instance,
                FltObjects->Volume,
                StreamContext->FileName,
                ByteOffset,
                ReadLength,
                &outReadBuffer,
                &BytesRead);

            if (!NT_SUCCESS(Status) || NULL == outReadBuffer)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReadFileNoCache1 failed. Status = 0x%x\n", __FUNCTION__, Status));
                Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                __leave;
            }

            BytesRead = (ULONG)(FileSize - (StartingVbo + LengthReturned));

            TempNewBuffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)LengthReturned + BytesRead, READ_BUFFER_TAG);

            if (NULL == TempNewBuffer)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag TempNewBuffer failed.\n", __FUNCTION__));
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                __leave;
            }

            RtlZeroMemory(TempNewBuffer, (SIZE_T)LengthReturned + BytesRead);

            TempOrigBuffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)LengthReturned + BytesRead, READ_BUFFER_TAG);

            if (NULL == TempOrigBuffer)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag TempOrigBuffer failed.\n", __FUNCTION__));
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                __leave;
            }

            RtlZeroMemory(TempOrigBuffer, (SIZE_T)LengthReturned + BytesRead);

            RtlMoveMemory(TempNewBuffer, NewBuffer, LengthReturned);
            RtlMoveMemory(TempNewBuffer + LengthReturned, outReadBuffer, BytesRead);

            Status = PocAesECBDecrypt_CiphertextStealing(TempNewBuffer, (ULONG)(LengthReturned + BytesRead), TempOrigBuffer);

            if (STATUS_SUCCESS != Status)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocAesECBDecrypt_CiphertextStealing1 failed.\n", __FUNCTION__));
                Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                __leave;
            }

            RtlMoveMemory(OrigBuffer, TempOrigBuffer, LengthReturned);
        }
        else if (FileSize > AES_BLOCK_SIZE &&
            LengthReturned < AES_BLOCK_SIZE)
        {
            PAGED_CODE();

            /*
            * 当文件大于一个块，Cache Manager将数据分多次读入缓冲，或者其他以NonCachedIo形式
            * 最后一次读的数据小于一个块时
            */

            Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, (PFLT_CONTEXT*)&VolumeContext);

            if (!NT_SUCCESS(Status) || 0 == VolumeContext->SectorSize)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltGetVolumeContext failed. Status = 0x%x\n", __FUNCTION__, Status));
                Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                __leave;
            }

            ByteOffset.QuadPart = StartingVbo - VolumeContext->SectorSize;
            ReadLength = VolumeContext->SectorSize;

            if (NULL != VolumeContext)
            {
                FltReleaseContext(VolumeContext);
                VolumeContext = NULL;
            }

            Status = PocReadFileNoCache(
                FltObjects->Instance,
                FltObjects->Volume,
                StreamContext->FileName,
                ByteOffset,
                ReadLength,
                &outReadBuffer,
                &BytesRead);

            if (!NT_SUCCESS(Status) || NULL == outReadBuffer)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReadFileNoCache2 failed. Status = 0x%x\n", __FUNCTION__, Status));
                Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                __leave;
            }

            ASSERT(ReadLength == BytesRead);

            TempNewBuffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)LengthReturned + BytesRead, READ_BUFFER_TAG);

            if (NULL == TempNewBuffer)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag TempNewBuffer failed.\n", __FUNCTION__));
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                __leave;
            }

            RtlZeroMemory(TempNewBuffer, (SIZE_T)LengthReturned + BytesRead);

            TempOrigBuffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)LengthReturned + BytesRead, READ_BUFFER_TAG);

            if (NULL == TempOrigBuffer)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag TempOrigBuffer failed.\n", __FUNCTION__));
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                __leave;
            }

            RtlZeroMemory(TempOrigBuffer, (SIZE_T)LengthReturned + BytesRead);

            RtlMoveMemory(TempNewBuffer, outReadBuffer, BytesRead);
            RtlMoveMemory(TempNewBuffer + BytesRead, NewBuffer, LengthReturned);

            Status = PocAesECBDecrypt_CiphertextStealing(TempNewBuffer, (ULONG)(LengthReturned + BytesRead), TempOrigBuffer);

            if (STATUS_SUCCESS != Status)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocAesECBDecrypt_CiphertextStealing2 failed.\n", __FUNCTION__));
                Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                __leave;
            }

            RtlMoveMemory(OrigBuffer, TempOrigBuffer + BytesRead, LengthReturned);
        }
        else if (LengthReturned % AES_BLOCK_SIZE != 0)
        {
            /*
            * 当需要读的数据大于一个块时，且和块大小不对齐时，这里用密文挪用的方式，不需要修改文件大小
            */

            Status = PocAesECBDecrypt_CiphertextStealing((PCHAR)NewBuffer, (ULONG)LengthReturned, (PCHAR)OrigBuffer);

            if (STATUS_SUCCESS != Status)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocAesECBDecrypt_CiphertextStealing2 failed.\n", __FUNCTION__));
                Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                __leave;
            }
        }
        else
        {
            /*
            * 当需要读的数据本身就和块大小对齐时，直接解密
            */
            Status = PocAesECBDecrypt((PCHAR)NewBuffer, (ULONG)LengthReturned, (PCHAR)OrigBuffer, &(ULONG)LengthReturned);

            if (STATUS_SUCCESS != Status)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocAesECBDecrypt failed.\n", __FUNCTION__));
                Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                __leave;
            }
        }

        /*
        * 此处bug已解决，原因如下
        * However, Unicode format codes (%wc and %ws) can be used only at IRQL=PASSIVE_LEVEL. 
        */

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Decrypt success. StartingVbo = %I64d Length = %d File = %s.\n\n",
            __FUNCTION__,
            Data->Iopb->Parameters.Read.ByteOffset.QuadPart,
            (ULONG)LengthReturned,
            SwapBufferContext->FileName));

    }
    finally
    {

        if (NULL != outReadBuffer)
        {
            FltFreePoolAlignedWithTag(FltObjects->Instance, outReadBuffer, READ_BUFFER_TAG);
            outReadBuffer = NULL;
        }

        if (NULL != TempNewBuffer)
        {
            ExFreePoolWithTag(TempNewBuffer, READ_BUFFER_TAG);
            TempNewBuffer = NULL;
        }

        if (NULL != TempOrigBuffer)
        {
            ExFreePoolWithTag(TempOrigBuffer, READ_BUFFER_TAG);
            TempOrigBuffer = NULL;
        }

    }

    return Status;
}
