
#include "fileinfo.h"
#include "context.h"
#include "utils.h"
#include "filefuncs.h"
#include "process.h"
#include "cipher.h"

FLT_POSTOP_CALLBACK_STATUS
PocPostSetInformationOperationWhenSafe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);


FLT_PREOP_CALLBACK_STATUS
PocPreQueryInformationOperation(
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

    PEPROCESS eProcess = NULL;
    HANDLE ProcessId = NULL;

    PPOC_CREATED_PROCESS_INFO OutProcessInfo = NULL;


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
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocFindOrCreateStreamContext failed. Status = 0x%x\n",
                __FUNCTION__,
                Status));
        }
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto EXIT;
    }

    Status = PocGetProcessName(Data, ProcessName);

    if (!StreamContext->IsCipherText && 0 == StreamContext->FileSize)
    {
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto EXIT;
    }

    if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION))
    {
        Status = FLT_PREOP_DISALLOW_FASTIO;
        goto EXIT;
    }

    try
    {
        eProcess = FltGetRequestorProcess(Data);

        if (NULL == eProcess)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->EProcess FltGetRequestorProcess failed.\n", __FUNCTION__));
            leave;
        }

        ProcessId = PsGetProcessId(eProcess);

        if (NULL == ProcessId)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                ("%s->PsGetProcessId %p failed.\n",
                    __FUNCTION__, eProcess));
            leave;
        }

        Status = PocFindProcessInfoNodeByPidEx(
            ProcessId,
            &OutProcessInfo,
            FALSE,
            FALSE);

    }
    except(EXCEPTION_EXECUTE_HANDLER)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Except 0x%x.\n", __FUNCTION__, GetExceptionCode()));
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto EXIT;
    }


    /*
    * 备份进程可以看到整个的文件，包括文件标识尾，所以不进入PostQuery去隐藏后续数据。
    * 
    * 具体的文件数据结构在PreRead中的注释里有画。
    */
    if (NULL != OutProcessInfo &&
        POC_PR_ACCESS_BACKUP == OutProcessInfo->OwnedProcessRule->Access)
    {
        Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
        goto EXIT;
    }

    /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\nPocPreQueryInformationOperation->enter FileInformationClass = %d ProcessName = %ws File = %ws.\n",
        Data->Iopb->Parameters.QueryFileInformation.FileInformationClass,
        ProcessName, StreamContext->FileName));*/

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
PocPostQueryInformationOperation(
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

    PPOC_STREAM_CONTEXT StreamContext = NULL;
    PVOID InfoBuffer = NULL;

    StreamContext = CompletionContext;
    InfoBuffer = Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;

    /*
    * StreamContext->FileSize记录着明文的大小，并写入到了标识尾中，这里是向上层隐藏"明文长度"之后数据的地方之一
    * 另一个地方在Read中，会对超过明文长度的CachedIo的授权进程和非授权进程隐藏后面的数据。
    */
    switch (Data->Iopb->Parameters.QueryFileInformation.FileInformationClass) {

    case FileStandardInformation:
    {
        PFILE_STANDARD_INFORMATION Info = (PFILE_STANDARD_INFORMATION)InfoBuffer;
        Info->EndOfFile.QuadPart = StreamContext->FileSize;
        break;
    }
    case FileAllInformation:
    {
        PFILE_ALL_INFORMATION Info = (PFILE_ALL_INFORMATION)InfoBuffer;
        if (Data->IoStatus.Information >=
            sizeof(FILE_BASIC_INFORMATION) +
            sizeof(FILE_STANDARD_INFORMATION))
        {
            Info->StandardInformation.EndOfFile.QuadPart = StreamContext->FileSize;
        }
        break;
    }
    case FileEndOfFileInformation:
    {
        PFILE_END_OF_FILE_INFORMATION Info = (PFILE_END_OF_FILE_INFORMATION)InfoBuffer;
        Info->EndOfFile.QuadPart = StreamContext->FileSize;
        break;
    }
    case FileNetworkOpenInformation:
    {
        PFILE_NETWORK_OPEN_INFORMATION Info = (PFILE_NETWORK_OPEN_INFORMATION)InfoBuffer;
        Info->EndOfFile.QuadPart = StreamContext->FileSize;
        break;
    }
    default:
    {
        break;
    }
    }


    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
PocPreSetInformationOperation(
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

    PVOID InfoBuffer = NULL;
    WCHAR ProcessName[POC_MAX_NAME_LENGTH] = { 0 };

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
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocFindOrCreateStreamContext failed. Status = 0x%x\n",
                __FUNCTION__,
                Status));
        }
        goto EXIT;
    }


    /*
    * 如果应用程序想要写入16个字节以内的数据，而且是以内存映射写入的话，是不会到CachedIo Write的，所以它会提前设置EOF，
    * 我们将它扩展到16个字节，以便AES对齐以后加密的密文能写入磁盘中。
    * 
    * 另一个扩展的地方在PreWrite->CachedIo
    */
    InfoBuffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

    switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass)
    {
    case FileEndOfFileInformation:
    {
        PFILE_END_OF_FILE_INFORMATION Info = (PFILE_END_OF_FILE_INFORMATION)InfoBuffer;

        if (Info->EndOfFile.QuadPart < AES_BLOCK_SIZE && Info->EndOfFile.QuadPart > 0)
        {
            ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

            StreamContext->FileSize = Info->EndOfFile.QuadPart;
            StreamContext->LessThanAesBlockSize = TRUE;

            ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

            Info->EndOfFile.QuadPart = (Info->EndOfFile.QuadPart / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

            Status = PocGetProcessName(Data, ProcessName);

            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->EndOfFile filename = %ws origin filesize = %I64d new filesize = %I64d process = %ws.\n",
                __FUNCTION__,
                StreamContext->FileName,
                StreamContext->FileSize,
                Info->EndOfFile.QuadPart,
                ProcessName));

            FltSetCallbackDataDirty(Data);
        }
        else if (0 == Info->EndOfFile.QuadPart)
        {
            ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

            StreamContext->FileSize = Info->EndOfFile.QuadPart;
            StreamContext->IsCipherText = FALSE;

            ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);
        }

        break;
    }
    case FileStandardInformation:
    {
        PFILE_STANDARD_INFORMATION Info = (PFILE_STANDARD_INFORMATION)InfoBuffer;

        if (Info->EndOfFile.QuadPart < AES_BLOCK_SIZE && Info->EndOfFile.QuadPart > 0)
        {
            Info->EndOfFile.QuadPart = (Info->EndOfFile.QuadPart / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

            ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

            StreamContext->FileSize = Info->EndOfFile.QuadPart;
            StreamContext->LessThanAesBlockSize = TRUE;

            ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

            /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->StandInfo EndOfFile filename = %ws origin filesize = %I64d new filesize = %I64d.\n",
                __FUNCTION__,
                StreamContext->FileName,
                StreamContext->FileSize,
                Info->EndOfFile.QuadPart));*/

            FltSetCallbackDataDirty(Data);
        }
        else if (0 == Info->EndOfFile.QuadPart)
        {
            ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

            StreamContext->FileSize = Info->EndOfFile.QuadPart;
            StreamContext->IsCipherText = FALSE;

            ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);
        }

        if (Info->AllocationSize.QuadPart < AES_BLOCK_SIZE && Info->AllocationSize.QuadPart > 0)
        {
            Info->AllocationSize.QuadPart = (Info->AllocationSize.QuadPart / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

            /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->StandInfo Alloc filename = %ws origin filesize = %I64d new filesize = %I64d.\n",
                __FUNCTION__,
                StreamContext->FileName,
                StreamContext->FileSize,
                Info->AllocationSize.QuadPart));*/

            FltSetCallbackDataDirty(Data);
        }

        break;
    }
    case FileAllocationInformation:
    {
        PFILE_ALLOCATION_INFORMATION Info = (PFILE_ALLOCATION_INFORMATION)InfoBuffer;

        if (Info->AllocationSize.QuadPart < AES_BLOCK_SIZE && Info->AllocationSize.QuadPart > 0)
        {
            Info->AllocationSize.QuadPart = (Info->AllocationSize.QuadPart / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

            /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->AllocInfo filename = %ws origin filesize = %I64d new filesize = %I64d.\n",
                __FUNCTION__,
                StreamContext->FileName,
                StreamContext->FileSize,
                Info->AllocationSize.QuadPart));*/

            FltSetCallbackDataDirty(Data);
        }
        
        break;
    }

    }

EXIT:

    Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return Status;
}


FLT_POSTOP_CALLBACK_STATUS
PocPostSetInformationOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    FLT_POSTOP_CALLBACK_STATUS Status = FLT_POSTOP_FINISHED_PROCESSING;

    if (!FltDoCompletionProcessingWhenSafe(Data,
        FltObjects,
        CompletionContext,
        Flags,
        PocPostSetInformationOperationWhenSafe,
        &Status))
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
            ("%s->FltDoCompletionProcessingWhenSafe failed. Status = 0x%x.\n",
                __FUNCTION__,
                Status));
    }

    return Status;
}


FLT_POSTOP_CALLBACK_STATUS
PocPostSetInformationOperationWhenSafe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PFILE_OBJECT TargetFileObject = NULL;
    PFILE_RENAME_INFORMATION Buffer = NULL;

    WCHAR NewFileName[POC_MAX_NAME_LENGTH] = { 0 };

    PPOC_STREAM_CONTEXT StreamContext = NULL;
    BOOLEAN ContextCreated = FALSE;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    HANDLE FileHandle = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    WCHAR ProcessName[POC_MAX_NAME_LENGTH] = { 0 };


    PAGED_CODE();

    if (STATUS_SUCCESS != Data->IoStatus.Status)
    {
        Status = FLT_POSTOP_FINISHED_PROCESSING;
        goto EXIT;
    }


    switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass)
    {
    case FileRenameInformation:
    case FileRenameInformationEx:
    {

        TargetFileObject = Data->Iopb->Parameters.SetFileInformation.ParentOfTarget;

        if (NULL == TargetFileObject)
        {
            Buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

            if (Buffer->FileNameLength < sizeof(NewFileName))
            {
                RtlMoveMemory(NewFileName, Buffer->FileName, Buffer->FileNameLength);
            }
        }
        else
        {
            if (NULL != TargetFileObject->FileName.Buffer &&
                TargetFileObject->FileName.MaximumLength < sizeof(NewFileName))
            {
                RtlMoveMemory(NewFileName, 
                    TargetFileObject->FileName.Buffer, 
                    TargetFileObject->FileName.MaximumLength);
            }
            else
            {
                goto EXIT;
            }
        }


        /*
        * 如果该文件之前是目标扩展名，那么我们的PostCreate一定为它建过StreamContext，
        * 所以这里可以凭借这点来判断文件原来是目标还是非目标扩展名。
        */
        Status = PocFindOrCreateStreamContext(
            Data->Iopb->TargetInstance,
            Data->Iopb->TargetFileObject,
            FALSE,
            &StreamContext,
            &ContextCreated);


        if (STATUS_SUCCESS == Status)
        {
            /*
            * 到这里，说明是目标扩展名改成目标或非目标扩展名，这里即便已经是密文，我们也不修改尾部里的FileName
            * 当再一次Create时，会由PostCreate->PocCreateFileForEncTailer判断文件名是否一致，
            * 不一致则会交给PostClose修改Tailer
            */

            Status = PocBypassIrrelevantBy_PathAndExtension(Data);

            if (POC_IRRELEVENT_FILE_EXTENSION == Status || NULL != TargetFileObject)
            {
                /*PocUpdateFlagInStreamContext(StreamContext, 0);*/

                ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

                StreamContext->IsCipherText = FALSE;
                StreamContext->FileSize = 0;
                RtlZeroMemory(StreamContext->FileName, POC_MAX_NAME_LENGTH * sizeof(WCHAR));

                ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
                    ("%s->Clear StreamContext NewFileName = %ws.\n", 
                    __FUNCTION__, NewFileName));

            }
            else
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocUpdateNameInStreamContext %ws to %ws.\n",
                    __FUNCTION__, StreamContext->FileName, NewFileName));

                Status = PocUpdateNameInStreamContext(StreamContext, NewFileName);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocUpdateNameInStreamContext failed. Status = 0x%x\n", __FUNCTION__, Status));
                    goto EXIT;
                }

            }

        }
        else if (STATUS_NOT_FOUND == Status)
        {

            /*
            * 到这里，说明原来的扩展名不是目标扩展名，因为没有进入PostCreate为其创建StreamContext
            */

            Status = PocBypassIrrelevantBy_PathAndExtension(Data);

            if (POC_IS_TARGET_FILE_EXTENSION == Status)
            {

                /*
                * 非目标扩展名改成了目标扩展名，为其创建StreamContext
                * 之所以单独创建StreamContext，而不是在下方的ZwCreateFile重入创建，
                * 是因为Create创建到回到PostSetInfo之间有段时间间隔，这段时间如果System写入数据，会导致文件被加密，
                * 我们的重入加密将不能再加密文件。
                * 所以我们提前抢占StreamContext的标识。
                */
                Status = PocFindOrCreateStreamContext(
                    Data->Iopb->TargetInstance,
                    Data->Iopb->TargetFileObject,
                    TRUE,
                    &StreamContext,
                    &ContextCreated);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->CtxFindOrCreateStreamContext failed. Status = 0x%x.\n",
                        __FUNCTION__, Status));
                    goto EXIT;
                }

                PocUpdateFlagInStreamContext(StreamContext, POC_RENAME_TO_ENCRYPT);


                /*
                * POC_IS_TARGET_FILE_EXTENSION说明文件改成目标扩展名
                * 重入一波，让我们的PostCreate读一下是否有Tailer(有可能是目标扩展名密文->其他扩展名->目标扩展名的情况)，
                */
                RtlZeroMemory(NewFileName, sizeof(NewFileName));

                PocGetFileNameOrExtension(Data, NULL, NewFileName);

                RtlInitUnicodeString(&uFileName, NewFileName);

                InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);


                Status = ZwCreateFile(
                    &FileHandle,
                    0,
                    &ObjectAttributes,
                    &IoStatusBlock,
                    NULL,
                    FILE_ATTRIBUTE_NORMAL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE,
                    NULL,
                    0);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ZwCreateFile failed. Status = 0x%x\n", __FUNCTION__, Status));
                    goto EXIT;
                }


                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->other extension rename to target extension NewFileName = %ws Flag = 0x%x.\n\n",
                    __FUNCTION__, NewFileName, StreamContext->Flag));


            }
        }
        else
        {
            Status = PocGetProcessName(Data, ProcessName);

            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocFindOrCreateStreamContext failed. Status = 0x%x ProcessName = %ws NewFileName = %ws\n",
                __FUNCTION__, Status, ProcessName, NewFileName));
        }

        break;
    }

    }

EXIT:

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    if (NULL != FileHandle)
    {
        FltClose(FileHandle);
        FileHandle = NULL;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}
