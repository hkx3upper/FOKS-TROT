

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
    PVOID OrigBuffer,
    PPOC_SWAP_BUFFER_CONTEXT *Context);


FLT_PREOP_CALLBACK_STATUS
PocPreReadOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    *CompletionContext = NULL;

    NTSTATUS Status;
    FLT_PREOP_CALLBACK_STATUS ret_status = FLT_PREOP_SUCCESS_NO_CALLBACK;

    WCHAR ProcessName[POC_MAX_NAME_LENGTH] = {0};

    PPOC_STREAM_CONTEXT StreamContext = NULL;
    BOOLEAN ContextCreated = FALSE;

    BOOLEAN NonCachedIo = BooleanFlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE);

    ULONG StartingVbo = Data->Iopb->Parameters.Read.ByteOffset.LowPart;
    ULONG ByteCount = Data->Iopb->Parameters.Read.Length; //以字节为单位

    PCHAR NewBuffer = NULL;
    PMDL NewMdl = NULL;

    PPOC_SWAP_BUFFER_CONTEXT SwapBufferContext = NULL;

    if (0 == ByteCount)
    {
        ret_status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto ERROR;
    }
    else
    {
        // TODO round_to_size
    }

    {
        Status = PocGetProcessName(Data, ProcessName);
        if (STATUS_SUCCESS != Status)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d: PocGetProcessName failed\n", __FUNCTION__, __FILE__, __LINE__));
            goto ERROR;
        }
        WCHAR FileName[POC_MAX_NAME_LENGTH] = {0};
        Status = PocGetFileNameOrExtension(Data, NULL, FileName);

        if (wcsstr(ProcessName, L"Video.UI.exe") != NULL && wcsstr(FileName, L"mp4") != NULL)
        {
            int a = 0;
            a = 1;
        }
    }

    { // Find StreamContext
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

            ret_status = FLT_PREOP_SUCCESS_NO_CALLBACK;
            goto ERROR;
        }

        if (!StreamContext->IsCipherText) //不是密文文件
        {
            // PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreReadOperation->leave. File is plaintext.\n"));
            ret_status = FLT_PREOP_SUCCESS_NO_CALLBACK;
            goto ERROR;
        }

        if (StartingVbo >= StreamContext->FileSize) //文件大小小于读取的起始位置
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreReadOperation->%ws read end of file.\n", ProcessName));
            Data->IoStatus.Status = STATUS_END_OF_FILE;
            Data->IoStatus.Information = 0;

            ret_status = FLT_PREOP_COMPLETE; 

            /*
            * The minifilter driver is completing the I/O operation. 
            * The filter manager does not send the I/O operation to any minifilter drivers 
            * below the caller in the driver stack or to the file system
            */
            
            goto ERROR;
        }
    }

    {
        if (!NonCachedIo)
        {
            if (StartingVbo + ByteCount > StreamContext->FileSize)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreReadOperation->%ws cachedio read end of file Length = %u. NewLength = %u\n",
                                                    ProcessName,
                                                    Data->Iopb->Parameters.Read.Length,
                                                    StreamContext->FileSize - StartingVbo));
                Data->Iopb->Parameters.Read.Length = StreamContext->FileSize - StartingVbo;
                ByteCount = Data->Iopb->Parameters.Read.Length;
                FltSetCallbackDataDirty(Data);
            }

            // CachedIo 不需要执行PostRead, 也不需要创建swappedbuffer
            ret_status = FLT_PREOP_SUCCESS_NO_CALLBACK;
            goto ERROR;
        }
    }

    { //创建交换缓冲区
        SwapBufferContext = (PPOC_SWAP_BUFFER_CONTEXT)ExAllocatePoolWithTag(NonPagedPool,
                                                                            sizeof(POC_SWAP_BUFFER_CONTEXT),
                                                                            READ_BUFFER_TAG);

        if (NULL == SwapBufferContext)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreReadOperation->ExAllocatePoolWithTag SwapBufferContext failed.\n"));
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            ret_status = FLT_PREOP_COMPLETE;
            goto ERROR;
        }
        RtlZeroMemory(SwapBufferContext, sizeof(POC_SWAP_BUFFER_CONTEXT));

        SwapBufferContext->StreamContext = StreamContext;
        *CompletionContext = SwapBufferContext;
        ret_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    // 参考PostCreateOperation中的做法，这里说明是非机密进程
    if (FltObjects->FileObject->SectionObjectPointer == StreamContext->ShadowSectionObjectPointers)
    {
        //为了隐藏文件标识尾，需要执行PostRead
        goto EXIT;
    }

    // 下面的过程都是 FltObjects->FileObject->SectionObjectPointer != StreamContext->ShadowSectionObjectPointers
    // 也即是在机密进程中
    { // NonCachedIo
        if (NonCachedIo && StreamContext->IsCipherText)
        {
            NewBuffer = (PCHAR)FltAllocatePoolAlignedWithTag(FltObjects->Instance,
                                                             NonPagedPool,
                                                             ByteCount,
                                                             READ_BUFFER_TAG);

            if (NULL == NewBuffer)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreReadOperation->FltAllocatePoolAlignedWithTag NewBuffer failed.\n"));
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                ret_status = FLT_PREOP_COMPLETE;
                goto ERROR;
            }

            RtlZeroMemory(NewBuffer, ByteCount);

            if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION))
            {

                NewMdl = IoAllocateMdl(NewBuffer, ByteCount, FALSE, FALSE, NULL);

                if (NewMdl == NULL)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreReadOperation->IoAllocateMdl NewMdl failed.\n"));
                    Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    Data->IoStatus.Information = 0;
                    ret_status = FLT_PREOP_COMPLETE;
                    goto ERROR;
                }

                MmBuildMdlForNonPagedPool(NewMdl);
            }

            SwapBufferContext->NewBuffer = NewBuffer;
            SwapBufferContext->NewMdl = NewMdl;

            Data->Iopb->Parameters.Read.ReadBuffer = NewBuffer;
            Data->Iopb->Parameters.Read.MdlAddress = NewMdl;
            FltSetCallbackDataDirty(Data);

            ret_status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
            goto EXIT;
        }
    }
ERROR:
    if (ret_status != FLT_PREOP_SUCCESS_WITH_CALLBACK)
    {
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

        *CompletionContext = NULL;
    }
EXIT:

    return ret_status;
}


FLT_POSTOP_CALLBACK_STATUS
PocPostReadOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
/*---------------------------------------------------------
函数名称: PocPostReadOperation
函数描述: Post Read的处理，主要包括数据的解密以及文件标识尾的隐藏
作者:     hkx3upper
更新维护: wangzhankun
---------------------------------------------------------*/
/*
* https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_post_operation_callback
*/
{
    UNREFERENCED_PARAMETER(Flags);

    ASSERT(CompletionContext != NULL);
    ASSERT(((PPOC_SWAP_BUFFER_CONTEXT)CompletionContext)->StreamContext != NULL);

    PVOID OrigBuffer = NULL;
    BOOLEAN clean_here = TRUE;

    FLT_POSTOP_CALLBACK_STATUS Status = FLT_POSTOP_FINISHED_PROCESSING;

    {
        PPOC_STREAM_CONTEXT StreamContext = ((PPOC_SWAP_BUFFER_CONTEXT)CompletionContext)->StreamContext;
        { // 隐藏文件标识尾
            ULONG StartingVbo = Data->Iopb->Parameters.Read.ByteOffset.LowPart;
            ULONG FileSize = StreamContext->FileSize;
            if (STATUS_SUCCESS == Data->IoStatus.Status)
            {
                if (StartingVbo + Data->IoStatus.Information > FileSize)
                {
                    Data->IoStatus.Information = FileSize - StartingVbo;
                }
            }
            else if (!NT_SUCCESS(Data->IoStatus.Status) || (Data->IoStatus.Information == 0))
            {
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                goto EXIT;
            }
        }

        { //非机密进程，不需要解密
            if (FltObjects->FileObject->SectionObjectPointer == StreamContext->ShadowSectionObjectPointers)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->Don't decrypt ciphertext cache map.\n"));
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                goto EXIT;
            }
        }
    }

    if (FlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE)                                     // noncachedio
        && ((PPOC_SWAP_BUFFER_CONTEXT)CompletionContext)->StreamContext != NULL       // streamcontext不为NULL
        && ((PPOC_SWAP_BUFFER_CONTEXT)CompletionContext)->StreamContext->IsCipherText // ciphertext
    )
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

                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->Failed to get system address for MDL1: %p\n",
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
                clean_here = FALSE;
            }
            else
            {
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
            }

            goto EXIT;
        }
        {
            PPOC_SWAP_BUFFER_CONTEXT tmp = (PPOC_SWAP_BUFFER_CONTEXT)CompletionContext;
            PocPostReadDecrypt(Data, FltObjects, OrigBuffer, &tmp);
            CompletionContext = tmp;
        }
    }
    Status = FLT_POSTOP_FINISHED_PROCESSING;

EXIT:

    if (CompletionContext != NULL && clean_here)
    {
        PPOC_SWAP_BUFFER_CONTEXT tmp = (PPOC_SWAP_BUFFER_CONTEXT)CompletionContext;
        if (tmp->NewBuffer)
        {
            FltFreePoolAlignedWithTag(FltObjects->Instance, tmp->NewBuffer, 'poc');
            tmp->NewBuffer = NULL;
        }
        if (tmp->StreamContext)
        {
            FltReleaseContext(tmp->StreamContext);
            tmp->StreamContext = NULL;
        }
        CompletionContext = NULL;
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
函数名称: PocPostReadOperationWhenSafe
函数描述: 如下
作者:     wangzhankun
更新维护: 
---------------------------------------------------------*/

/*++

Routine Description:

    We had an arbitrary users buffer without a MDL so we needed to get
    to a safe IRQL so we could lock it and then copy the data.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - Contains state from our PreOperation callback

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    FLT_POSTOP_FINISHED_PROCESSING - This is always returned.

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PVOID origBuf = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    FLT_ASSERT(Data->IoStatus.Information != 0);

    // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltlockuserbuffer
    // <= APC_LEVEL
    // FltLockUserBuffer sets the MdlAddress (or OutputMdlAddress) member in the callback data parameter structure (FLT_PARAMETERS) to point to the MDL for the locked pages. If there is no MDL, FltLockUserBuffer allocates one.
    status = FltLockUserBuffer(Data); // 不需要使用者手动释放

    if (status != STATUS_SUCCESS)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d: FltLockUserBuffer failed.\n", __FUNCTION__, __FILE__, __LINE__));
        Data->IoStatus.Status = status;
        Data->IoStatus.Information = 0;
    }
    else
    {
        // Get a system address for the buffer
        origBuf = MmGetSystemAddressForMdlSafe(iopb->Parameters.Read.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
        if (origBuf == NULL)
        {
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
        }
        else
        {
            // Here will always have a system buffer address.
            PPOC_SWAP_BUFFER_CONTEXT tmp = (PPOC_SWAP_BUFFER_CONTEXT)CompletionContext;
            PocPostReadDecrypt(Data, FltObjects, origBuf, &tmp);
            CompletionContext = tmp;
        }
    }

    if (CompletionContext != NULL)
    {
        PPOC_SWAP_BUFFER_CONTEXT tmp = (PPOC_SWAP_BUFFER_CONTEXT)CompletionContext;
        if (tmp->NewBuffer)
        {
            FltFreePoolAlignedWithTag(FltObjects->Instance, tmp->NewBuffer, 'poc');
            tmp->NewBuffer = NULL;
        }
        if (tmp->StreamContext)
        {
            FltReleaseContext(tmp->StreamContext);
            tmp->StreamContext = NULL;
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}


NTSTATUS PocPostReadDecrypt(_Inout_ PFLT_CALLBACK_DATA Data,
                            _In_ PCFLT_RELATED_OBJECTS FltObjects,
                            PVOID OrigBuffer,
                            PPOC_SWAP_BUFFER_CONTEXT *Context)
{
    auto ret_status = FLT_POSTOP_FINISHED_PROCESSING;

    __try
    {
        ASSERT(Context);
        PPOC_SWAP_BUFFER_CONTEXT SwapBufferContext = *Context;
        ASSERT(SwapBufferContext);
        PPOC_STREAM_CONTEXT StreamContext = SwapBufferContext->StreamContext;
        ASSERT(StreamContext);

        ULONG StartingVbo = Data->Iopb->Parameters.Read.ByteOffset.LowPart;

        /*
        * This is set to a request-dependent value. For example, on successful completion of a transfer request, 
        * this is set to the number of bytes transferred. 
        * If a transfer request is completed with another STATUS_XXX, this member is set to zero.
        */
        ULONG LengthReturned = (ULONG)Data->IoStatus.Information;
        ULONG FileSize = StreamContext->FileSize;

        LARGE_INTEGER byteOffset = {0};
        ULONG readLength = 0;
        PCHAR outReadBuffer = NULL;
        ULONG bytesRead = 0;

        PCHAR TempNewBuffer = NULL;
        PCHAR TempOrigBuffer = NULL;

        PVOID NewBuffer = SwapBufferContext->NewBuffer;

        PPOC_VOLUME_CONTEXT VolumeContext = NULL;

        NTSTATUS Status;

        __try
        {

            if (FileSize < AES_BLOCK_SIZE)
            {
                LengthReturned = AES_BLOCK_SIZE;

                Status = PocAesECBDecrypt(NewBuffer, LengthReturned, OrigBuffer, &LengthReturned);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->PocAesECBDecrypt1 failed.\n"));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    Status = FLT_POSTOP_FINISHED_PROCESSING;
                    __leave;
                }
            }
            else if ((FileSize > StartingVbo + LengthReturned) &&
                     (FileSize - (StartingVbo + LengthReturned) < AES_BLOCK_SIZE))
            {
                /*
                 * 当文件大于一个块，Cache Manager将数据分多次读入缓冲，或者其他以NonCachedIo形式
                 * 最后一次读的数据小于一个块的情况下，现在在倒数第二个块做一下处理
                 */

                byteOffset.LowPart = StartingVbo + LengthReturned;
                readLength = AES_BLOCK_SIZE;

                Status = PocReadFileNoCache(
                    FltObjects->Instance,
                    FltObjects->Volume,
                    StreamContext->FileName,
                    byteOffset,
                    readLength,
                    &outReadBuffer,
                    &bytesRead);

                if (!NT_SUCCESS(Status) || NULL == outReadBuffer)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->PocReadFileNoCache1 failed. Status = 0x%x\n", Status));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    ret_status = FLT_POSTOP_FINISHED_PROCESSING;
                    __leave;
                }

                bytesRead = FileSize - (StartingVbo + LengthReturned);

                TempNewBuffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)LengthReturned + bytesRead, READ_BUFFER_TAG);

                if (NULL == TempNewBuffer)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->ExAllocatePoolWithTag TempNewBuffer failed.\n"));
                    Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    Data->IoStatus.Information = 0;
                    ret_status = FLT_POSTOP_FINISHED_PROCESSING;
                    __leave;
                }

                // RtlZeroMemory(TempNewBuffer, (SIZE_T)LengthReturned + bytesRead);//无意义

                TempOrigBuffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)LengthReturned + bytesRead, READ_BUFFER_TAG);

                if (NULL == TempOrigBuffer)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->ExAllocatePoolWithTag TempOrigBuffer failed.\n"));
                    Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    Data->IoStatus.Information = 0;
                    ret_status = FLT_POSTOP_FINISHED_PROCESSING;
                    __leave;
                }

                RtlZeroMemory(TempOrigBuffer, (SIZE_T)LengthReturned + bytesRead);

                RtlMoveMemory(TempNewBuffer, NewBuffer, LengthReturned);
                RtlMoveMemory(TempNewBuffer + LengthReturned, outReadBuffer, bytesRead);

                Status = PocAesECBDecrypt_CiphertextStealing(TempNewBuffer, LengthReturned + bytesRead, TempOrigBuffer);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->PocAesECBDecrypt_CiphertextStealing1 failed.\n"));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    ret_status = FLT_POSTOP_FINISHED_PROCESSING;
                    __leave;
                }

                RtlMoveMemory(OrigBuffer, TempOrigBuffer, LengthReturned);
            }
            else if (FileSize > AES_BLOCK_SIZE &&
                     LengthReturned < AES_BLOCK_SIZE)
            {
                /*
                 * 当文件大于一个块，Cache Manager将数据分多次读入缓冲，或者其他以NonCachedIo形式
                 * 最后一次读的数据小于一个块时
                 */

                Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, (PFLT_CONTEXT *)&VolumeContext);

                if (!NT_SUCCESS(Status) || 0 == VolumeContext->SectorSize)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->FltGetVolumeContext failed. Status = 0x%x\n", Status));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    ret_status = FLT_POSTOP_FINISHED_PROCESSING;
                    __leave;
                }

                byteOffset.LowPart = StartingVbo - VolumeContext->SectorSize;
                readLength = VolumeContext->SectorSize;

                if (NULL != VolumeContext)
                {
                    FltReleaseContext(VolumeContext);
                    VolumeContext = NULL;
                }

                Status = PocReadFileNoCache(
                    FltObjects->Instance,
                    FltObjects->Volume,
                    StreamContext->FileName,
                    byteOffset,
                    readLength,
                    &outReadBuffer,
                    &bytesRead);

                if (!NT_SUCCESS(Status) || NULL == outReadBuffer)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->PocReadFileNoCache2 failed. Status = 0x%x\n", Status));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    ret_status = FLT_POSTOP_FINISHED_PROCESSING;
                    __leave;
                }

                ASSERT(readLength == bytesRead);

                TempNewBuffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)LengthReturned + bytesRead, READ_BUFFER_TAG);

                if (NULL == TempNewBuffer)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->ExAllocatePoolWithTag TempNewBuffer failed.\n"));
                    Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    Data->IoStatus.Information = 0;
                    ret_status = FLT_POSTOP_FINISHED_PROCESSING;
                    __leave;
                }

                RtlZeroMemory(TempNewBuffer, (SIZE_T)LengthReturned + bytesRead);

                TempOrigBuffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)LengthReturned + bytesRead, READ_BUFFER_TAG);

                if (NULL == TempOrigBuffer)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->ExAllocatePoolWithTag TempOrigBuffer failed.\n"));
                    Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    Data->IoStatus.Information = 0;
                    ret_status = FLT_POSTOP_FINISHED_PROCESSING;
                    __leave;
                }

                RtlZeroMemory(TempOrigBuffer, (SIZE_T)LengthReturned + bytesRead);

                RtlMoveMemory(TempNewBuffer, outReadBuffer, bytesRead);
                RtlMoveMemory(TempNewBuffer + bytesRead, NewBuffer, LengthReturned);

                Status = PocAesECBDecrypt_CiphertextStealing(TempNewBuffer, LengthReturned + bytesRead, TempOrigBuffer);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->PocAesECBDecrypt_CiphertextStealing2 failed.\n"));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    ret_status = FLT_POSTOP_FINISHED_PROCESSING;
                    __leave;
                }

                RtlMoveMemory(OrigBuffer, TempOrigBuffer + bytesRead, LengthReturned);
            }
            else if (LengthReturned % AES_BLOCK_SIZE != 0)
            {
                /*
                 * 当需要读的数据大于一个块时，且和块大小不对齐时，这里用密文挪用的方式，不需要修改文件大小
                 */

                Status = PocAesECBDecrypt_CiphertextStealing((PCHAR)NewBuffer, LengthReturned, (PCHAR)OrigBuffer);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->PocAesECBDecrypt_CiphertextStealing2 failed.\n"));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    ret_status = FLT_POSTOP_FINISHED_PROCESSING;
                    __leave;
                }
            }
            else
            {
                /*
                 * 当需要读的数据本身就和块大小对齐时，直接解密
                 */
                Status = PocAesECBDecrypt((PCHAR)NewBuffer, LengthReturned, (PCHAR)OrigBuffer, &LengthReturned);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->PocAesECBDecrypt failed.\n"));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    ret_status = FLT_POSTOP_FINISHED_PROCESSING;
                    __leave;
                }
            }
        }
        __finally
        {

            if (NULL != StreamContext)
            {
                if (NULL != StreamContext->FileName)
                {
                    // PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileName = %ws\n", StreamContext->FileName));
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s, FileName address is %p\n", __FUNCTION__, StreamContext->FileName));
                    // PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%p\n", StreamContext->FileName));
                }
                else
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s,FileName = NULL\n", __FUNCTION__));
                }
            }
            else
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s, StreamContext = NULL\n", __FUNCTION__));
            }

            if (NULL != NewBuffer)
            {
                FltFreePoolAlignedWithTag(FltObjects->Instance, NewBuffer, READ_BUFFER_TAG);
                NewBuffer = NULL;
                SwapBufferContext->NewBuffer = NULL;
            }

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

            if (NULL != StreamContext)
            {
                FltReleaseContext(StreamContext); // PreRead函数中 PocFindOrCreateStreamContext 会Get一次，因此这里需要Release一次
                StreamContext = NULL;
                SwapBufferContext->StreamContext = NULL;
            }

            if (NULL != SwapBufferContext)
            {
                ExFreePoolWithTag(SwapBufferContext, READ_BUFFER_TAG);
                SwapBufferContext = NULL;
                *Context = NULL;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Data->IoStatus.Status = GetExceptionCode();
        Data->IoStatus.Information = 0;
        ret_status = FLT_POSTOP_FINISHED_PROCESSING;
    }

    return STATUS_SUCCESS;
}
