

#include "read.h"
#include "context.h"
#include "utils.h"
#include "write.h"
#include "cipher.h"
#include "filefuncs.h"
#include "process.h"


FLT_PREOP_CALLBACK_STATUS
PocPreReadOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    NTSTATUS Status;

    WCHAR ProcessName[POC_MAX_NAME_LENGTH] = { 0 };

    PPOC_STREAM_CONTEXT StreamContext = NULL;
    BOOLEAN ContextCreated = FALSE;

    BOOLEAN NonCachedIo = FALSE;
    BOOLEAN PagingIo = FALSE;

    ULONG StartingVbo = 0, ByteCount = 0;

    PCHAR NewBuffer = NULL;
    PMDL NewMdl = NULL;

    PPOC_SWAP_BUFFER_CONTEXT SwapBufferContext = NULL;

    ByteCount = Data->Iopb->Parameters.Read.Length;

    NonCachedIo = BooleanFlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE);
    PagingIo = BooleanFlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO);


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

    Status = PocGetProcessName(Data, ProcessName);

    if (!StreamContext->IsCipherText)
    {
        //PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreReadOperation->leave. File is plaintext.\n"));
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto ERROR;
    }

    
    //PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\nPocPreReadOperation->enter StartingVbo = %d Length = %d ProcessName = %ws File = %ws.\n NonCachedIo = %d PagingIo = %d\n",
    //    Data->Iopb->Parameters.Read.ByteOffset.LowPart,
    //    Data->Iopb->Parameters.Read.Length,
    //    ProcessName, StreamContext->FileName,
    //    NonCachedIo,
    //    PagingIo));
    

    StartingVbo = Data->Iopb->Parameters.Read.ByteOffset.LowPart;

    if (StartingVbo >= StreamContext->FileSize)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreReadOperation->%ws read end of file.\n", ProcessName));
        Data->IoStatus.Status = STATUS_END_OF_FILE;
        Data->IoStatus.Information = 0;

        Status = FLT_PREOP_COMPLETE;
        goto ERROR;
    }

    if (!NonCachedIo && StartingVbo + ByteCount > StreamContext->FileSize)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreReadOperation->%ws cachedio read end of file Length = %d. NewLength = %d\n", 
            ProcessName, 
            Data->Iopb->Parameters.Read.Length,
            StreamContext->FileSize - StartingVbo));
        Data->Iopb->Parameters.Read.Length = StreamContext->FileSize - StartingVbo;
        FltSetCallbackDataDirty(Data);
    }

    SwapBufferContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(POC_SWAP_BUFFER_CONTEXT), READ_BUFFER_TAG);

    if (NULL == SwapBufferContext)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreReadOperation->ExAllocatePoolWithTag SwapBufferContext failed.\n"));
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        Status = FLT_PREOP_COMPLETE;
        goto ERROR;
    }

    RtlZeroMemory(SwapBufferContext, sizeof(POC_SWAP_BUFFER_CONTEXT));

    if (FltObjects->FileObject->SectionObjectPointer
        == StreamContext->ShadowSectionObjectPointers)
    {
        SwapBufferContext->StreamContext = StreamContext;
        *CompletionContext = SwapBufferContext;
        Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
        goto EXIT;
    }


    if (NonCachedIo && StreamContext->IsCipherText)
    {
        NewBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, ByteCount, READ_BUFFER_TAG);

        if (NULL == NewBuffer)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPreReadOperation->FltAllocatePoolAlignedWithTag NewBuffer failed.\n"));
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            Status = FLT_PREOP_COMPLETE;
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
                Status = FLT_PREOP_COMPLETE;
                goto ERROR;
            }

            MmBuildMdlForNonPagedPool(NewMdl);
        }

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
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    ASSERT(CompletionContext != NULL);
    ASSERT(((PPOC_SWAP_BUFFER_CONTEXT)CompletionContext)->StreamContext != NULL);

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PPOC_SWAP_BUFFER_CONTEXT SwapBufferContext = NULL;
    PPOC_STREAM_CONTEXT StreamContext = NULL;

    ULONG StartingVbo = 0, LengthReturned = 0, FileSize = 0;
    BOOLEAN NonCachedIo = FALSE, PagingIo = FALSE;

    PCHAR OrigBuffer = NULL, NewBuffer = NULL;
    PMDL NewMdl = NULL;

    LARGE_INTEGER byteOffset = { 0 };
    ULONG readLength = 0;
    PCHAR outReadBuffer = NULL;
    ULONG bytesRead = 0;

    PCHAR TempNewBuffer = NULL;
    PCHAR TempOrigBuffer = NULL;

    PPOC_VOLUME_CONTEXT VolumeContext = NULL;

    WCHAR ProcessName[POC_MAX_NAME_LENGTH] = { 0 };

    SwapBufferContext = CompletionContext;
    StreamContext = SwapBufferContext->StreamContext;

    StartingVbo = Data->Iopb->Parameters.Read.ByteOffset.LowPart;
    FileSize = StreamContext->FileSize;

    NonCachedIo = BooleanFlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE);
    PagingIo = BooleanFlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO);


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



    if (FltObjects->FileObject->SectionObjectPointer 
        == StreamContext->ShadowSectionObjectPointers)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->Don't decrypt ciphertext cache map.\n"));
        Status = FLT_POSTOP_FINISHED_PROCESSING;
        goto EXIT;
    }


    if (NonCachedIo && StreamContext->IsCipherText)
    {
        LengthReturned = (ULONG)Data->IoStatus.Information;

        NewBuffer = SwapBufferContext->NewBuffer;
        NewMdl = SwapBufferContext->NewMdl;

        if (Data->Iopb->Parameters.Read.MdlAddress != NULL) 
        {

            FLT_ASSERT(((PMDL)Data->Iopb->Parameters.Read.MdlAddress)->Next == NULL);

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
            OrigBuffer = Data->Iopb->Parameters.Read.ReadBuffer;
        }
        else
        {
            PAGED_CODE();

            Status = FltLockUserBuffer(Data);

            if (STATUS_SUCCESS != Status)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->FltLockUserBuffer failed. Status = 0x%X.\n"));
                Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                goto EXIT;
            }

            OrigBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Read.MdlAddress,
                NormalPagePriority | MdlMappingNoExecute);

            if (OrigBuffer == NULL)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->Failed to get system address for MDL2: %p\n",
                    Data->Iopb->Parameters.Read.MdlAddress));

                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                Status = FLT_POSTOP_FINISHED_PROCESSING;
                goto EXIT;

            }

        }


        try
        {

            if (FileSize < AES_BLOCK_SIZE)
            {
                /*
                * 文件小于一个块，采用流式解密
                */
                PocStreamModeDecrypt(NewBuffer, LengthReturned, OrigBuffer);

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
                    Status = FLT_POSTOP_FINISHED_PROCESSING;
                    goto EXIT;
                }

                bytesRead = FileSize - (StartingVbo + LengthReturned);

                TempNewBuffer = ExAllocatePoolWithTag(NonPagedPool, LengthReturned + bytesRead, READ_BUFFER_TAG);

                if (NULL == TempNewBuffer)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->ExAllocatePoolWithTag TempNewBuffer failed.\n"));
                    Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    Data->IoStatus.Information = 0;
                    Status = FLT_POSTOP_FINISHED_PROCESSING;
                    goto EXIT;
                }

                RtlZeroMemory(TempNewBuffer, LengthReturned + bytesRead);

                TempOrigBuffer= ExAllocatePoolWithTag(NonPagedPool, LengthReturned + bytesRead, READ_BUFFER_TAG);

                if (NULL == TempOrigBuffer)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->ExAllocatePoolWithTag TempOrigBuffer failed.\n"));
                    Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    Data->IoStatus.Information = 0;
                    Status = FLT_POSTOP_FINISHED_PROCESSING;
                    goto EXIT;
                }

                RtlZeroMemory(TempOrigBuffer, LengthReturned + bytesRead);


                RtlMoveMemory(TempNewBuffer, NewBuffer, LengthReturned);
                RtlMoveMemory(TempNewBuffer + LengthReturned, outReadBuffer, bytesRead);

                Status = PocAesECBDecrypt_CiphertextStealing(TempNewBuffer, LengthReturned + bytesRead, TempOrigBuffer);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->PocAesECBDecrypt_CiphertextStealing1 failed.\n"));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    Status = FLT_POSTOP_FINISHED_PROCESSING;
                    goto EXIT;
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

                Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &VolumeContext);

                if (!NT_SUCCESS(Status) || 0 == VolumeContext->SectorSize)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->FltGetVolumeContext failed. Status = 0x%x\n", Status));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    Status = FLT_POSTOP_FINISHED_PROCESSING;
                    goto EXIT;
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
                    Status = FLT_POSTOP_FINISHED_PROCESSING;
                    goto EXIT;
                }

                ASSERT(readLength == bytesRead);

                TempNewBuffer = ExAllocatePoolWithTag(NonPagedPool, LengthReturned + bytesRead, READ_BUFFER_TAG);

                if (NULL == TempNewBuffer)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->ExAllocatePoolWithTag TempNewBuffer failed.\n"));
                    Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    Data->IoStatus.Information = 0;
                    Status = FLT_POSTOP_FINISHED_PROCESSING;
                    goto EXIT;
                }

                RtlZeroMemory(TempNewBuffer, LengthReturned + bytesRead);

                TempOrigBuffer = ExAllocatePoolWithTag(NonPagedPool, LengthReturned + bytesRead, READ_BUFFER_TAG);

                if (NULL == TempOrigBuffer)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->ExAllocatePoolWithTag TempOrigBuffer failed.\n"));
                    Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                    Data->IoStatus.Information = 0;
                    Status = FLT_POSTOP_FINISHED_PROCESSING;
                    goto EXIT;
                }

                RtlZeroMemory(TempOrigBuffer, LengthReturned + bytesRead);

                RtlMoveMemory(TempNewBuffer, outReadBuffer, bytesRead);
                RtlMoveMemory(TempNewBuffer + bytesRead, NewBuffer, LengthReturned);

                Status = PocAesECBDecrypt_CiphertextStealing(TempNewBuffer, LengthReturned + bytesRead, TempOrigBuffer);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->PocAesECBDecrypt_CiphertextStealing2 failed.\n"));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    Status = FLT_POSTOP_FINISHED_PROCESSING;
                    goto EXIT;
                }

                RtlMoveMemory(OrigBuffer, TempOrigBuffer + bytesRead, LengthReturned);

            }
            else if (LengthReturned % AES_BLOCK_SIZE != 0)
            {
                /*
                * 当需要读的数据大于一个块时，且和块大小不对齐时，这里用密文挪用的方式，不需要修改文件大小
                */

                Status = PocAesECBDecrypt_CiphertextStealing(NewBuffer, LengthReturned, OrigBuffer);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->PocAesECBDecrypt_CiphertextStealing2 failed.\n"));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    Status = FLT_POSTOP_FINISHED_PROCESSING;
                    goto EXIT;
                }

            }
            else
            {
                /*
                * 当需要读的数据本身就和块大小对齐时，直接解密
                */

                Status = PocAesECBDecrypt(NewBuffer, LengthReturned, OrigBuffer, &LengthReturned);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->PocAesECBDecrypt failed.\n"));
                    Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                    Data->IoStatus.Information = 0;
                    Status = FLT_POSTOP_FINISHED_PROCESSING;
                    goto EXIT;
                }

            }


        }
        except(EXCEPTION_EXECUTE_HANDLER)
        {
            Data->IoStatus.Status = GetExceptionCode();
            Data->IoStatus.Information = 0;
            Status = FLT_POSTOP_FINISHED_PROCESSING;
            goto EXIT;
        }


        Status = PocGetProcessName(Data, ProcessName);

        /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->Decrypt success. StartingVbo = %d Length = %d ProcessName = %ws File = %ws.\n\n",
            StartingVbo,
            LengthReturned,
            ProcessName, 
            StreamContext->FileName));*/


        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocPostReadOperation->Decrypt success. StartingVbo = %d Length = %d ProcessName = %s\n",
            StartingVbo,
            LengthReturned,
            ProcessName));

        if (NULL != StreamContext)
        {
            if (NULL != StreamContext->FileName)
            {
                // PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileName = %ws\n", StreamContext->FileName));
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s, FileName address is 0x%016x\n", __FUNCTION__, StreamContext->FileName));
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

       
    }

    Status = FLT_POSTOP_FINISHED_PROCESSING;

EXIT:

    if (NULL != NewBuffer)
    {
        FltFreePoolAlignedWithTag(FltObjects->Instance, NewBuffer, READ_BUFFER_TAG);
        NewBuffer = NULL;
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

    if (NULL != SwapBufferContext)
    {
        ExFreePoolWithTag(SwapBufferContext, READ_BUFFER_TAG);
        SwapBufferContext = NULL;
    }

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return Status;
}
