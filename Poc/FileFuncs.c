
#include "filefuncs.h"
#include "context.h"
#include "global.h"
#include "utils.h"

POC_ENCRYPTION_HEADER EncryptionHeader = { 0 };

POC_ENCRYPTION_TAILER EncryptionTailer = { 0 };

NTSTATUS PocReadFileNoCache(
    IN PFLT_INSTANCE Instance,
    IN PFLT_VOLUME Volume,
    IN PWCHAR FileName,
    IN LARGE_INTEGER ByteOffset,
    IN ULONG ReadLength,
    OUT PCHAR* OutReadBuffer, 
    IN OUT PULONG BytesRead)
{
    
    //ReadBuffer需要函数返回STATUS_SUCCESS后，调用者手动释放
    //FltFreePoolAlignedWithTag(FltObjects->Instance, ReadBuffer, READ_BUFFER_TAG);

    if (NULL == FileName)
    {
        DbgPrint("PocReadFileNoCache->FileName is NULL.\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == BytesRead)
    {
        DbgPrint("PocReadFileNoCache->BytesRead is NULL.\n");
        return STATUS_INVALID_PARAMETER;
    }

    PAGED_CODE();

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PPOC_VOLUME_CONTEXT VolumeContext = NULL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    ULONG FileSize = 0;
    PCHAR ReadBuffer = NULL;
    LARGE_INTEGER byteOffset = { 0 };
    ULONG readLength = 0;

    byteOffset.QuadPart = ByteOffset.QuadPart;
    readLength = ReadLength;

    Status = FltGetVolumeContext(gFilterHandle, Volume, &VolumeContext);

    if (!NT_SUCCESS(Status) || 0 == VolumeContext->SectorSize) 
    {
        DbgPrint("PocReadFileNoCache->FltGetVolumeContext failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);


    Status = FltCreateFileEx(
        gFilterHandle,
        Instance,
        &hFile,
        &FileObject,
        GENERIC_READ,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_NO_INTERMEDIATE_BUFFERING,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocReadFileNoCache->FltCreateFileEx failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    FileSize = PocQueryEndOfFileInfo(Instance, FileObject);

    if (byteOffset.LowPart + readLength > FileSize)
    {
        DbgPrint("PocReadFileNoCache->End of File.\n");
        Status = STATUS_END_OF_FILE;
        goto EXIT;
    }

    readLength = ROUND_TO_SIZE(readLength, VolumeContext->SectorSize);
    byteOffset.LowPart = ROUND_TO_SIZE(byteOffset.LowPart, VolumeContext->SectorSize);

    //FLTFL_IO_OPERATION_NON_CACHED
    //The ReadBuffer that the Buffer parameter points to must be aligned 
    //in accordance with the alignment requirement of the underlying storage device. 
    //To allocate such an aligned buffer, call FltAllocatePoolAlignedWithTag.
    ReadBuffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, readLength, READ_BUFFER_TAG);

    if (NULL == ReadBuffer)
    {
        DbgPrint("PocReadFileNoCache->FltAllocatePoolAlignedWithTag ReadBuffer failed.\\n");
        Status = STATUS_UNSUCCESSFUL;
        goto EXIT;
    }

    RtlZeroMemory(ReadBuffer, readLength);

    Status = FltReadFileEx(
        Instance, 
        FileObject, 
        &byteOffset, 
        readLength, 
        ReadBuffer,
        FLTFL_IO_OPERATION_NON_CACHED | 
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | 
        FLTFL_IO_OPERATION_PAGING | 
        FLTFL_IO_OPERATION_SYNCHRONOUS_PAGING, 
        BytesRead, 
        NULL, 
        NULL, 
        NULL, 
        NULL);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("PocReadFileNoCache->FltReadFileEx failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    *OutReadBuffer = ReadBuffer;

EXIT:

    if (NULL != VolumeContext)
    {
        FltReleaseContext(VolumeContext);
        VolumeContext = NULL;
    }

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    if (!NT_SUCCESS(Status) && NULL != ReadBuffer)
    {
        FltFreePoolAlignedWithTag(Instance, ReadBuffer, READ_BUFFER_TAG);
        ReadBuffer = NULL;
        *OutReadBuffer = NULL;
    }

	return Status;
}


NTSTATUS PocReadFileFromCache(
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject,
    IN LARGE_INTEGER ByteOffset,
    IN PCHAR ReadBuffer,
    IN ULONG ReadLength)
{

    if (NULL == ReadBuffer)
    {
        DbgPrint("PocReadFileFromCache->ReadBuffer is NULL.\n");
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    Status = FltReadFileEx(Instance, FileObject, &ByteOffset, ReadLength, ReadBuffer, 0, NULL, NULL, NULL, NULL, NULL);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocReadFileFromCache->FltReadFileEx failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

EXIT:

    return Status;
}


NTSTATUS PocWriteFileIntoCache(
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject,
    IN LARGE_INTEGER ByteOffset,
    IN PCHAR WriteBuffer,
    IN ULONG WriteLength)
{

    if (NULL == WriteBuffer)
    {
        DbgPrint("PocWriteFileIntoCache->WriteBuffer is NULL.\n");
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    ULONG BytesWritten = 0;

    Status = FltWriteFileEx(Instance, FileObject, &ByteOffset, WriteLength, WriteBuffer, 0, &BytesWritten, NULL, NULL, NULL, NULL);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocWriteFileIntoCache->FltWriteFileEx failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

EXIT:

    return Status;
}


#if 0
NTSTATUS PocCreateExtraFileForEncryptionHeader(
    IN PFLT_CALLBACK_DATA Data,
    IN PWCHAR FileName)
{
    if (NULL == FileName)
    {
        DbgPrint("PocCreateExtraFileForEncryptionHeader->FileName is NULL.\n");
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    WCHAR ExtraFileName[POC_MAX_NAME_LENGTH] = { 0 };
    PWCHAR lpFileName = NULL;
    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    PCHAR Buffer = NULL;

    RtlMoveMemory(ExtraFileName, FileName, wcslen(FileName) * sizeof(WCHAR));

    lpFileName = ExtraFileName + wcslen(ExtraFileName) * 2;

    while (lpFileName != ExtraFileName)
    {
        if ('.' == *lpFileName)
        {
            lpFileName++;

            RtlZeroMemory(lpFileName, wcslen(lpFileName) * sizeof(WCHAR));
            RtlMoveMemory(lpFileName, L"POC", wcslen(L"POC") * sizeof(WCHAR));

            break;
        }
        lpFileName--;
    }

    if (lpFileName == ExtraFileName)
    {
        DbgPrint("PocCreateExtraFileForEncryptionHeader->FileName error.\\n");
        Status = STATUS_UNSUCCESSFUL;
        goto EXIT;
    }

    RtlInitUnicodeString(&uFileName, ExtraFileName);

    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    Buffer = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, WRITE_BUFFER_TAG);

    if (NULL == Buffer)
    {
        DbgPrint("PocCreateExtraFileForEncryptionHeader->ExAllocatePoolWithTag Buffer failed.\\n");
        Status = STATUS_UNSUCCESSFUL;
        goto EXIT;
    }


    if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
        (FILE_WRITE_DATA | FILE_APPEND_DATA)))
    {
        Status = FltCreateFileEx(gFilterHandle, Data->Iopb->TargetInstance, &hFile, &FileObject, GENERIC_READ | GENERIC_WRITE,
            &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL/*FILE_ATTRIBUTE_HIDDEN*/,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH, NULL, 0, 0);

        if (STATUS_SUCCESS != Status)
        {
            DbgPrint("PocCreateExtraFileForEncryptionHeader->FltCreateFileEx1 failed. Status = 0x%x\n", Status);
            goto EXIT;
        }

        if (FILE_CREATED == IoStatusBlock.Information)
        {

            RtlZeroMemory(Buffer, PAGE_SIZE);

            RtlZeroMemory(EncryptionHeader.FileName, sizeof(EncryptionHeader.FileName));

            RtlMoveMemory(EncryptionHeader.FileName, FileName, wcslen(FileName) * sizeof(WCHAR));

            RtlMoveMemory(Buffer, &EncryptionHeader, sizeof(POC_ENCRYPTION_HEADER));

            Status = PocWriteFileIntoCache(
                Data->Iopb->TargetInstance,
                FileObject,
                Buffer,
                PAGE_SIZE);

            if (STATUS_SUCCESS != Status)
            {
                DbgPrint("PocCreateExtraFileForEncryptionHeader->PocWriteFileIntoCache failed. Status = 0x%x\n", Status);
                goto EXIT;
            }

            Status = POC_FILE_HAS_ENCRYPTION_HEADER;
            goto EXIT;
        }
    }

    if (NULL == FileObject)
    {
        Status = FltCreateFileEx(gFilterHandle, Data->Iopb->TargetInstance, &hFile, &FileObject, GENERIC_READ,
            &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
            FILE_NON_DIRECTORY_FILE, NULL, 0, 0);

        if (STATUS_SUCCESS != Status)
        {
            //DbgPrint("PocCreateExtraFileForEncryptionHeader->FltCreateFileEx2 failed. Status = 0x%x\n", Status);
            goto EXIT;
        }
    }

    RtlZeroMemory(Buffer, PAGE_SIZE);

    Status = PocReadFileFromCache(
        Data->Iopb->TargetInstance,
        FileObject,
        Buffer,
        PAGE_SIZE);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocCreateExtraFileForEncryptionHeader->PocReadFileFromCache failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    if (strncmp(Buffer, EncryptionHeader.Flag, strlen(EncryptionHeader.Flag)) == 0 &&
        wcsncmp(((PPOC_ENCRYPTION_HEADER)Buffer)->FileName, FileName,
            wcslen(FileName) * sizeof(WCHAR)) == 0)
    {
        Status = POC_FILE_HAS_ENCRYPTION_HEADER;
    }

EXIT:
    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    if (Buffer != NULL)
    {
        ExFreePoolWithTag(Buffer, WRITE_BUFFER_TAG);
        Buffer = NULL;
    }

    return Status;
}
#endif // 0


NTSTATUS PocCreateFileForEncTailer(
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN PPOC_STREAM_CONTEXT StreamContext,
    IN PCHAR ProcessName)
{

    if (NULL == StreamContext)
    {
        DbgPrint("PocCreateFileForEncTailer->StreamContext is NULL.\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == StreamContext->FileName)
    {
        DbgPrint("PocCreateFileForEncTailer->StreamContext->FileName is NULL.\n");
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    ULONG FileSize = 0;
    LARGE_INTEGER ByteOffset = { 0 };
    PCHAR OutReadBuffer = NULL;
    ULONG BytesRead = 0;


    FileSize = PocQueryEndOfFileInfo(FltObjects->Instance, FltObjects->FileObject);

    if (FileSize < PAGE_SIZE)
    {
        Status = STATUS_END_OF_FILE;
        goto EXIT;
    }

    //PocReadFileNoCache里面会对ByteOffset对齐0x200
    ByteOffset.LowPart = FileSize - PAGE_SIZE;


    Status = PocReadFileNoCache(
        FltObjects->Instance,
        FltObjects->Volume,
        StreamContext->FileName,
        ByteOffset,
        PAGE_SIZE,
        &OutReadBuffer,
        &BytesRead);

    if (!NT_SUCCESS(Status) || NULL == OutReadBuffer)
    {
        DbgPrint("PocCreateFileForEncTailer->PocReadFileNoCache failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    if (strncmp(((PPOC_ENCRYPTION_TAILER)OutReadBuffer)->Flag, EncryptionTailer.Flag, 
        strlen(EncryptionTailer.Flag)) == 0 &&
        wcsncmp(((PPOC_ENCRYPTION_TAILER)OutReadBuffer)->FileName, StreamContext->FileName,
            wcslen(StreamContext->FileName)) == 0)
    {

        /*
        * 驱动加载后，文件如果有缓冲或者被内存映射读写过，清一下缓冲，防止出现密文
        * 但对于非授权进程不需要，因为它不使用该缓冲
        * IsCipherText == 0，说明是在驱动加载以后，第一次被打开
        */
        Status = PocIsUnauthorizedProcess(ProcessName);

        if (0 == StreamContext->IsCipherText &&
            POC_IS_AUTHORIZED_PROCESS == Status)
        {
            if (FltObjects->FileObject->SectionObjectPointer->DataSectionObject != NULL)
            {
                Status = PocNtfsFlushAndPurgeCache(FltObjects->Instance, FltObjects->FileObject);

                if (STATUS_SUCCESS != Status)
                {
                    DbgPrint("PocCreateFileForEncTailer->PocNtfsFlushAndPurgeCache failed. Status = 0x%x\n", Status);
                }
                else
                {
                    DbgPrint("PocCreateFileForEncTailer->File has been opened. Flush and purge cache.\n");
                }
            }
        }

        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

        if (0 == StreamContext->FileSize)
        {
            StreamContext->FileSize = ((PPOC_ENCRYPTION_TAILER)OutReadBuffer)->FileSize;
        }
        if (0 == StreamContext->IsCipherText)
        {
            StreamContext->IsCipherText = ((PPOC_ENCRYPTION_TAILER)OutReadBuffer)->IsCipherText;
        }
        
        ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

        Status = POC_FILE_HAS_ENCRYPTION_TAILER;

        DbgPrint("\nPocCreateFileForEncTailer->File %ws has encryption tailer FileSize = %d.\n",
            StreamContext->FileName,
            FileSize);
    }
    else if(strncmp(((PPOC_ENCRYPTION_TAILER)OutReadBuffer)->Flag, EncryptionTailer.Flag,
        strlen(EncryptionTailer.Flag)) == 0)
    {
        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

        if (0 == StreamContext->FileSize)
        {
            StreamContext->FileSize = ((PPOC_ENCRYPTION_TAILER)OutReadBuffer)->FileSize;
        }
        if (0 == StreamContext->IsCipherText)
        {
            StreamContext->IsCipherText = ((PPOC_ENCRYPTION_TAILER)OutReadBuffer)->IsCipherText;
        }

        ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

        Status = POC_TAILER_WRONG_FILE_NAME;

        DbgPrint("PocCreateFileForEncTailer->Ciphetext->other extension->target extension.\n");
    }


EXIT:
    if (NULL != OutReadBuffer)
    {
        FltFreePoolAlignedWithTag(FltObjects->Instance, OutReadBuffer, READ_BUFFER_TAG);
        OutReadBuffer = NULL;
    }

    return Status;
}


NTSTATUS PocAppendEncTailerToFile(
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN PPOC_STREAM_CONTEXT StreamContext)
{
    if (NULL == StreamContext)
    {
        DbgPrint("PocAppendEncTailerToFile->StreamContext is NULL.\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == StreamContext->FileName)
    {
        DbgPrint("PocAppendEncTailerToFile->StreamContext->FileName is NULL.\n");
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PPOC_VOLUME_CONTEXT VolumeContext = NULL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    ULONG FileSize = 0;
    LARGE_INTEGER ByteOffset = { 0 };
    ULONG WriteLength = 0;
    PCHAR WriteBuffer = NULL;
    ULONG BytesWritten = 0;


    Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &VolumeContext);

    if (!NT_SUCCESS(Status) || 0 == VolumeContext->SectorSize)
    {
        DbgPrint("PocAppendEncTailerToFile->FltGetVolumeContext failed. Status = 0x%x\n", Status);
        goto EXIT;
    }


    RtlInitUnicodeString(&uFileName, StreamContext->FileName);

    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = FltCreateFileEx(
        gFilterHandle,
        FltObjects->Instance,
        &hFile,
        &FileObject,
        GENERIC_WRITE,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_NO_INTERMEDIATE_BUFFERING,
        NULL,
        0,
        0);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocAppendEncTailerToFile->FltCreateFileEx failed. Status = 0x%x\n", Status);
        goto EXIT;
    }


    FileSize = StreamContext->FileSize;

    WriteLength = ROUND_TO_SIZE(PAGE_SIZE, VolumeContext->SectorSize);

    WriteBuffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, WriteLength, WRITE_BUFFER_TAG);

    if (NULL == WriteBuffer)
    {
        DbgPrint("PocAppendEncTailerToFile->FltAllocatePoolAlignedWithTag WriteBuffer failed.\\n");
        Status = STATUS_UNSUCCESSFUL;
        goto EXIT;
    }

    RtlZeroMemory(WriteBuffer, WriteLength);

    ByteOffset.LowPart = ROUND_TO_SIZE(FileSize, VolumeContext->SectorSize);

    RtlZeroMemory(EncryptionTailer.FileName, sizeof(EncryptionTailer.FileName));
    RtlMoveMemory(EncryptionTailer.FileName, StreamContext->FileName, wcslen(StreamContext->FileName) * sizeof(WCHAR));
    EncryptionTailer.FileSize = StreamContext->FileSize;
    EncryptionTailer.IsCipherText = StreamContext->IsCipherText;

    RtlMoveMemory(WriteBuffer, &EncryptionTailer, sizeof(POC_ENCRYPTION_TAILER));

    Status = FltWriteFileEx(
        FltObjects->Instance,
        FileObject,
        &ByteOffset,
        WriteLength,
        WriteBuffer,
        FLTFL_IO_OPERATION_NON_CACHED |
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
        &BytesWritten,
        NULL,
        NULL,
        NULL,
        NULL);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("PocAppendEncTailerToFile->FltWriteFileEx failed. Status = 0x%x\n", Status);
        goto EXIT;
    }
    

EXIT:

    if (NULL != VolumeContext)
    {
        FltReleaseContext(VolumeContext);
        VolumeContext = NULL;
    }

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    if (NULL != WriteBuffer)
    {
        FltFreePoolAlignedWithTag(FltObjects->Instance, WriteBuffer, WRITE_BUFFER_TAG);
        WriteBuffer = NULL;
    }

    return Status;
}


NTSTATUS PocNtfsFlushAndPurgeCache(
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PFLT_CALLBACK_DATA Data = NULL;

    Status = FltAllocateCallbackData(Instance, FileObject, &Data);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocNtfsFlushAndPurgeCache->FltAllocateCallbackData failed. Status = 0x%x\n", Status);
        return Status;
    }

    Data->Iopb->MajorFunction = IRP_MJ_FLUSH_BUFFERS;
    Data->Iopb->MinorFunction = IRP_MN_FLUSH_AND_PURGE;
    Data->Iopb->IrpFlags = IRP_SYNCHRONOUS_API;
    FltPerformSynchronousIo(Data);

    return Data->IoStatus.Status;
}


NTSTATUS PocFlushOriginalCache(
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN PWCHAR FileName)
{
    if (NULL == FileName)
    {
        DbgPrint("PocFlushOriginalCache->FileName is NULL.\n");
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };


    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = FltCreateFileEx(
        gFilterHandle,
        FltObjects->Instance,
        &hFile,
        &FileObject,
        0,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0,
        IO_IGNORE_SHARE_ACCESS_CHECK);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocFlushOriginalCache->FltCreateFileEx failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    if (CcIsFileCached(FileObject))
    {
        Status = FltFlushBuffers(FltObjects->Instance, FileObject);

        if (STATUS_SUCCESS != Status)
        {
            DbgPrint("PocFlushOriginalCache->FltFlushBuffers failed. Status = 0x%x\n", Status);
            goto EXIT;
        }
    }


EXIT:

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    return Status;
}


NTSTATUS PocReentryToGetStreamContext(
    IN PFLT_INSTANCE Instance,
    IN PWCHAR FileName,
    OUT PPOC_STREAM_CONTEXT* StreamContext)
{
    if (NULL == FileName)
    {
        DbgPrint("PocReentryToGetStreamContext->FileName is NULL.\n");
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    BOOLEAN ContextCreated = FALSE;


    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(
        &ObjectAttributes,
        &uFileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    Status = ZwCreateFile(
        &hFile,
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
        DbgPrint("PocReentryToGetStreamContext->ZwCreateFile failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    Status = ObReferenceObjectByHandle(hFile, STANDARD_RIGHTS_ALL, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocReentryToGetStreamContext->ObReferenceObjectByHandle failed ststus = 0x%x.\n", Status);
        goto EXIT;
    }

    Status = PocFindOrCreateStreamContext(
        Instance,
        FileObject,
        FALSE,
        StreamContext,
        &ContextCreated);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocReentryToGetStreamContext->PocFindOrCreateStreamContext failed. Status = 0x%x\n", Status);
        goto EXIT;
    }


EXIT:

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    if (NULL != hFile)
    {
        ZwClose(hFile);
        hFile = NULL;
    }
    
    return Status;
}


NTSTATUS PocReentryToEncrypt(
    IN PFLT_INSTANCE Instance,
    IN PWCHAR FileName)
{
    if (NULL == FileName)
    {
        DbgPrint("PocDirectEncrypt->FileName is NULL.\n");
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PPOC_STREAM_CONTEXT StreamContext = NULL;

    ULONG FileSize = 0;
    LARGE_INTEGER ByteOffset = { 0 };
    PCHAR ReadBuffer = NULL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };


    Status = PocReentryToGetStreamContext(
        Instance,
        FileName,
        &StreamContext);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectEncrypt->PocReentryToGetStreamContext failed. Status = 0x%x\n", Status);
        if (STATUS_NOT_FOUND == Status)
        {
            Status = POC_IRRELEVENT_FILE_EXTENSION;
        }
        goto EXIT;
    }

    if (TRUE == StreamContext->IsCipherText)
    {
        Status = POC_FILE_IS_CIPHERTEXT;
        DbgPrint("PocDirectEncrypt->%ws is ciphertext. Encrypt failed.\n", FileName);
        goto EXIT;
    }


    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(
        &ObjectAttributes, 
        &uFileName, 
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 
        NULL, 
        NULL);

    Status = FltCreateFileEx(
        gFilterHandle,
        Instance,
        &hFile,
        &FileObject,
        GENERIC_READ,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        0);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectEncrypt->FltCreateFileEx failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    FileSize = PocQueryEndOfFileInfo(Instance, FileObject);

    if(0 == FileSize)
    {
        DbgPrint("PocDirectEncrypt->FileSize is zero.\n");
        Status = STATUS_SUCCESS;
        goto EXIT;
    }

    ReadBuffer = ExAllocatePoolWithTag(NonPagedPool, FileSize, READ_BUFFER_TAG);

    if (NULL == ReadBuffer)
    {
        DbgPrint("PocDirectEncrypt->ExAllocatePoolWithTag ReadBuffer failed.\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto EXIT;
    }

    RtlZeroMemory(ReadBuffer, FileSize);

    ByteOffset.QuadPart = 0;

    Status = PocReadFileFromCache(
        Instance,
        FileObject,
        ByteOffset,
        ReadBuffer,
        FileSize);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectEncrypt->PocReadFileFromCache failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }




    RtlZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    InitializeObjectAttributes(
        &ObjectAttributes,
        &uFileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);


    Status = ZwCreateFile(
        &hFile,
        GENERIC_WRITE,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_WRITE_THROUGH,
        NULL,
        0);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectEncrypt->ZwCreateFile failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    Status = ObReferenceObjectByHandle(
        hFile, 
        STANDARD_RIGHTS_ALL, 
        *IoFileObjectType, 
        KernelMode, 
        (PVOID*)&FileObject, 
        NULL);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectEncrypt->ObReferenceObjectByHandle failed. Status = 0x%x.\n", Status);
        goto EXIT;
    }


    ByteOffset.QuadPart = 0;

    Status = PocWriteFileIntoCache(
        Instance,
        FileObject,
        ByteOffset,
        ReadBuffer,
        FileSize);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectEncrypt->PocWriteFileIntoCache failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    DbgPrint("\nPocDirectEncrypt->success. FileName = %ws FileSize = %d.\n", 
        FileName, 
        ((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->FileSize.LowPart);

EXIT:

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    if (NULL != ReadBuffer)
    {
        ExFreePoolWithTag(ReadBuffer, READ_BUFFER_TAG);
        ReadBuffer = NULL;
    }

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    return Status;
}


NTSTATUS PocReentryToDecrypt(
    IN PFLT_INSTANCE Instance,
    IN PWCHAR FileName)
{
    if (NULL == FileName)
    {
        DbgPrint("PocDirectDecrypt->FileName is NULL.\n");
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PPOC_STREAM_CONTEXT StreamContext = NULL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    ULONG FileSize = 0;
    LARGE_INTEGER ByteOffset = { 0 };
    
    PCHAR ReadBuffer = NULL;
    PCHAR WriteBuffer = NULL;

    ULONG WriteLength = 0, BytesWritten = 0;

    Status = PocReentryToGetStreamContext(
        Instance, 
        FileName, 
        &StreamContext);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectDecrypt->PocReentryToGetStreamContext failed. Status = 0x%x\n", Status);
        if (STATUS_NOT_FOUND == Status)
        {
            Status = POC_IRRELEVENT_FILE_EXTENSION;
        }
        goto EXIT;
    }

    if (FALSE == StreamContext->IsCipherText)
    {
        Status = POC_FILE_IS_PLAINTEXT;
        DbgPrint("PocDirectDecrypt->%ws is plaintext. Decrypt failed.\n", FileName);
        goto EXIT;
    }

    PocUpdateFlagInStreamContext(StreamContext, 0);

    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(
        &ObjectAttributes,
        &uFileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    Status = ZwCreateFile(
        &hFile,
        GENERIC_READ,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectDecrypt->ZwCreateFile failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    Status = ObReferenceObjectByHandle(
        hFile, 
        STANDARD_RIGHTS_ALL, 
        *IoFileObjectType, 
        KernelMode, 
        (PVOID*)&FileObject, 
        NULL);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectDecrypt->ObReferenceObjectByHandle failed. Status = 0x%x.\n", Status);
        goto EXIT;
    }

    FileSize = StreamContext->FileSize;

    ReadBuffer = ExAllocatePoolWithTag(NonPagedPool, FileSize, READ_BUFFER_TAG);

    if (NULL == ReadBuffer)
    {
        DbgPrint("PocDirectDecrypt->ExAllocatePoolWithTag ReadBuffer failed.\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto EXIT;
    }

    RtlZeroMemory(ReadBuffer, FileSize);

    ByteOffset.QuadPart = 0;

    Status = PocReadFileFromCache(
        Instance, 
        FileObject,
        ByteOffset,
        ReadBuffer,
        FileSize);


    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectDecrypt->PocReadFileFromCache failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    Status = PocSetEndOfFileInfo(
        Instance,
        FileObject,
        FileSize);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectDecrypt->PocSetEndOfFileInfo failed. Status = 0x%x\n", Status);
        goto EXIT;
    }

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }




    RtlZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    InitializeObjectAttributes(
        &ObjectAttributes,
        &uFileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    Status = FltCreateFileEx(
        gFilterHandle,
        Instance,
        &hFile,
        &FileObject,
        GENERIC_WRITE,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_NO_INTERMEDIATE_BUFFERING,
        NULL,
        0,
        0);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectDecrypt->FltCreateFileEx failed. Status = 0x%x\n", Status);
        goto EXIT;
    }


    WriteLength = ROUND_TO_PAGES(FileSize);

    WriteBuffer= FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, WriteLength, WRITE_BUFFER_TAG);

    if (NULL == WriteBuffer)
    {
        DbgPrint("PocDirectDecrypt->FltAllocatePoolAlignedWithTag WriteBuffer failed.\\n");
        Status = STATUS_UNSUCCESSFUL;
        goto EXIT;
    }

    RtlZeroMemory(WriteBuffer, WriteLength);

    RtlMoveMemory(WriteBuffer, ReadBuffer, FileSize);

    ByteOffset.QuadPart = 0;

    Status = FltWriteFileEx(
        Instance,
        FileObject,
        &ByteOffset,
        WriteLength,
        WriteBuffer,
        FLTFL_IO_OPERATION_NON_CACHED |
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET |
        FLTFL_IO_OPERATION_PAGING |
        FLTFL_IO_OPERATION_SYNCHRONOUS_PAGING,
        &BytesWritten,
        NULL,
        NULL,
        NULL,
        NULL);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectDecrypt->FltWriteFileEx failed. Status = 0x%x\n", Status);
        goto EXIT;
    }


    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    Status = FltDeleteStreamContext(Instance, FileObject, NULL);

    if (STATUS_SUCCESS != Status)
    {
        DbgPrint("PocDirectDecrypt->FltDeleteStreamContext failed. Status = 0x%x\n", Status);
    }
    else
    {
        DbgPrint("\nPocDirectDecrypt->FltDeleteStreamContext FileName = %ws.\n", FileName);
    }
    

    DbgPrint("PocDirectDecrypt->success. FileName = %ws FileSize = %d.\n\n", 
        FileName, 
        ((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->FileSize.LowPart);

EXIT:

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    if (NULL != FileObject)
    {
        ObDereferenceObject(FileObject);
        FileObject = NULL;
    }

    if (NULL != ReadBuffer)
    {
        ExFreePoolWithTag(ReadBuffer, READ_BUFFER_TAG);
        ReadBuffer = NULL;
    }

    if (NULL != WriteBuffer)
    {
        FltFreePoolAlignedWithTag(Instance, WriteBuffer, WRITE_BUFFER_TAG);
        WriteBuffer = NULL;
    }

    return Status;
}
