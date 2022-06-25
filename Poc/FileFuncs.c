
#include "filefuncs.h"
#include "context.h"
#include "process.h"
#include "global.h"
#include "utils.h"
#include "write.h"
#include "cipher.h"

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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->FileName is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == BytesRead)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->BytesRead is NULL.\n"));
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

    LONGLONG FileSize = 0;
    PCHAR ReadBuffer = NULL;
    LARGE_INTEGER byteOffset = { 0 };
    ULONG readLength = 0;

    byteOffset.QuadPart = ByteOffset.QuadPart;
    readLength = ReadLength;

    Status = FltGetVolumeContext(gFilterHandle, Volume, &VolumeContext);

    if (!NT_SUCCESS(Status) || 0 == VolumeContext->SectorSize) 
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->FltGetVolumeContext failed. Status = 0x%x\n", Status));
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->FltCreateFileEx failed. Status = 0x%x\n", Status));
        goto EXIT;
    }

    FileSize = PocQueryEndOfFileInfo(Instance, FileObject);

    if (byteOffset.QuadPart + readLength > FileSize)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->End of File.\n"));
        Status = STATUS_END_OF_FILE;
        goto EXIT;
    }

    readLength = ROUND_TO_SIZE(readLength, VolumeContext->SectorSize);
    byteOffset.QuadPart = ROUND_TO_SIZE(byteOffset.QuadPart, VolumeContext->SectorSize);

    //FLTFL_IO_OPERATION_NON_CACHED
    //The ReadBuffer that the Buffer parameter points to must be aligned 
    //in accordance with the alignment requirement of the underlying storage device. 
    //To allocate such an aligned buffer, call FltAllocatePoolAlignedWithTag.
    ReadBuffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, readLength, READ_BUFFER_TAG);

    if (NULL == ReadBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->FltAllocatePoolAlignedWithTag ReadBuffer failed.\n"));
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
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, 
        BytesRead, 
        NULL, 
        NULL, 
        NULL, 
        NULL);

    if (!NT_SUCCESS(Status))
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->FltReadFileEx failed. Status = 0x%x\n", Status));
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileFromCache->ReadBuffer is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    Status = FltReadFileEx(Instance, FileObject, &ByteOffset, ReadLength, ReadBuffer, 0, NULL, NULL, NULL, NULL, NULL);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileFromCache->FltReadFileEx failed. Status = 0x%x\n", Status));
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocWriteFileIntoCache->WriteBuffer is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    ULONG BytesWritten = 0;

    Status = FltWriteFileEx(Instance, FileObject, &ByteOffset, WriteLength, WriteBuffer, 0, &BytesWritten, NULL, NULL, NULL, NULL);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocWriteFileIntoCache->FltWriteFileEx failed. Status = 0x%x\n", Status));
        goto EXIT;
    }

EXIT:

    return Status;
}


NTSTATUS PocCreateFileForEncTailer(
    IN PCFLT_RELATED_OBJECTS FltObjects,
    IN PPOC_STREAM_CONTEXT StreamContext,
    IN PWCHAR ProcessName)
{

    if (NULL == StreamContext)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateFileForEncTailer->StreamContext is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == StreamContext->FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateFileForEncTailer->StreamContext->FileName is NULL.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    LONGLONG FileSize = 0;
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
    ByteOffset.QuadPart = FileSize - PAGE_SIZE;


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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReadFileNoCache failed. ProcessName = %ws Status = 0x%x\n", __FUNCTION__, ProcessName, Status));
        goto EXIT;
    }

    if (strncmp(((PPOC_ENCRYPTION_TAILER)OutReadBuffer)->Flag, EncryptionTailer.Flag, 
        strlen(EncryptionTailer.Flag)) == 0 &&
        wcsncmp(((PPOC_ENCRYPTION_TAILER)OutReadBuffer)->FileName, StreamContext->FileName,
            wcslen(StreamContext->FileName)) == 0)
    {

        /*
        * 驱动加载后，文件如果有缓冲或者被内存映射读写过，清一下缓冲，防止出现密文
        * 只要驱动加载之前有缓冲，都要清掉。
        */
        if (0 == StreamContext->IsCipherText)
        {
            if (FltObjects->FileObject->SectionObjectPointer->DataSectionObject != NULL)
            {
                Status = PocNtfsFlushAndPurgeCache(FltObjects->Instance, FltObjects->FileObject);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateFileForEncTailer->PocNtfsFlushAndPurgeCache failed. Status = 0x%x.\n", Status));
                }
                else
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateFileForEncTailer->File has been opened. Flush and purge cache.\n"));
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

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\n%s->File %ws has encryption tailer FileSize = %I64d ProcessName = %ws.\n",
            __FUNCTION__,
            StreamContext->FileName,
            StreamContext->FileSize,
            ProcessName));
    }
    else if(strncmp(((PPOC_ENCRYPTION_TAILER)OutReadBuffer)->Flag, EncryptionTailer.Flag,
        strlen(EncryptionTailer.Flag)) == 0)
    {
        if (0 == StreamContext->IsCipherText)
        {
            if (FltObjects->FileObject->SectionObjectPointer->DataSectionObject != NULL)
            {
                Status = PocNtfsFlushAndPurgeCache(FltObjects->Instance, FltObjects->FileObject);

                if (STATUS_SUCCESS != Status)
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateFileForEncTailer->PocNtfsFlushAndPurgeCache failed. Status = 0x%x.\n", Status));
                }
                else
                {
                    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocCreateFileForEncTailer->File has been opened. Flush and purge cache.\n"));
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

        Status = POC_TAILER_WRONG_FILE_NAME;

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Ciphetext->other extension->target extension. FileSize = %I64d ProcessName = %ws\n",
            __FUNCTION__,
            StreamContext->FileSize,
            ProcessName));
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
    IN PFLT_VOLUME Volume,
    IN PFLT_INSTANCE Instance,
    IN PPOC_STREAM_CONTEXT StreamContext)
{
    if (NULL == StreamContext)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->StreamContext is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == StreamContext->FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->StreamContext->FileName is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PPOC_VOLUME_CONTEXT VolumeContext = NULL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    LONGLONG FileSize = 0;
    LARGE_INTEGER ByteOffset = { 0 };
    ULONG WriteLength = 0;
    PCHAR WriteBuffer = NULL;
    ULONG BytesWritten = 0;

    Status = FltGetVolumeContext(gFilterHandle, Volume, &VolumeContext);

    if (!NT_SUCCESS(Status) || 0 == VolumeContext->SectorSize)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltGetVolumeContext failed. Status = 0x%x.\n", __FUNCTION__, Status));
        goto EXIT;
    }


    RtlInitUnicodeString(&uFileName, StreamContext->FileName);

    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

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
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0,
        0);

    if (STATUS_SUCCESS != Status)
    {
        if (STATUS_OBJECT_NAME_NOT_FOUND == Status ||
            STATUS_OBJECT_PATH_SYNTAX_BAD == Status)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltCreateFileEx Status = 0x%x. Success->It means that the file has been deleted.\n", __FUNCTION__, Status));
        }
        else
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltCreateFileEx failed. Status = 0x%x.\n", __FUNCTION__, Status));
        }
        goto EXIT;
    }

    /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\n %s->Process = %p Thread = %p Fcb = %p Ccb = %p Resource = %p PagingIoResource = %p.\n\n",
        __FUNCTION__,
        PsGetCurrentProcess(),
        PsGetCurrentThread(),
        (PCHAR)FileObject->FsContext,
        FileObject->FsContext2,
        ((PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext)->Resource,
        ((PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext)->PagingIoResource));*/


    FileSize = StreamContext->FileSize;

    WriteLength = ROUND_TO_SIZE(PAGE_SIZE, VolumeContext->SectorSize);

    WriteBuffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, WriteLength, WRITE_BUFFER_TAG);

    if (NULL == WriteBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltAllocatePoolAlignedWithTag WriteBuffer failed.\n", __FUNCTION__));
        Status = STATUS_UNSUCCESSFUL;
        goto EXIT;
    }

    RtlZeroMemory(WriteBuffer, WriteLength);

    ByteOffset.QuadPart = ROUND_TO_SIZE(FileSize, VolumeContext->SectorSize);


    RtlMoveMemory(WriteBuffer, &EncryptionTailer, sizeof(POC_ENCRYPTION_TAILER));

    ((PPOC_ENCRYPTION_TAILER)WriteBuffer)->FileSize = StreamContext->FileSize;;
    ((PPOC_ENCRYPTION_TAILER)WriteBuffer)->IsCipherText = StreamContext->IsCipherText;
    RtlMoveMemory(((PPOC_ENCRYPTION_TAILER)WriteBuffer)->FileName, StreamContext->FileName, wcslen(StreamContext->FileName) * sizeof(WCHAR));


    Status = FltWriteFileEx(
        Instance,
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltWriteFileEx failed. Status = 0x%x.\n", __FUNCTION__, Status));
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



    if (NULL != StreamContext->ShadowSectionObjectPointers->DataSectionObject)
    {

        Status = FltCreateFileEx(
            gFilterHandle,
            Instance,
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
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltCreateFileEx failed. Status = 0x%x\n", __FUNCTION__, Status));
            goto EXIT;
        }

        FileObject->SectionObjectPointer = StreamContext->ShadowSectionObjectPointers;

        if (NULL == StreamContext->ShadowSectionObjectPointers->SharedCacheMap)
        {
            CHAR Buffer = { 0 };
            ByteOffset.QuadPart = 0;

            Status = FltReadFileEx(Instance, FileObject, &ByteOffset,
                sizeof(Buffer), &Buffer, 0, NULL, NULL, NULL, NULL, NULL);

            if (!NT_SUCCESS(Status) && STATUS_END_OF_FILE != Status)
            {
                PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitShadowSectionObjectPointers->FltReadFileEx init ciphertext cache failed. Status = 0x%x\n", Status));
                goto EXIT;
            }
        }


        if (CcIsFileCached(FileObject))
        {
            ExAcquireResourceExclusiveLite(((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->Resource, TRUE);

            CcSetFileSizes(
                FileObject,
                (PCC_FILE_SIZES) & ((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->AllocationSize);

            CcPurgeCacheSection(StreamContext->ShadowSectionObjectPointers, NULL, 0, FALSE);

            ExReleaseResourceLite(((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->Resource);


            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                ("%s->CcSetFileSizes chipertext cache map size.\nFile = %ws AllocationSize = %I64d ValidDataLength = %I64d FileSize = %I64d SCM = %d DSO = %d.\n\n",
                    __FUNCTION__,
                    StreamContext->FileName,
                    ((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->AllocationSize.QuadPart,
                    ((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->ValidDataLength.QuadPart,
                    ((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->FileSize.QuadPart,
                    NULL == StreamContext->ShadowSectionObjectPointers->SharedCacheMap ? 0 : 1,
                    NULL == StreamContext->ShadowSectionObjectPointers->DataSectionObject ? 0 : 1));
        }
        
    }


    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

    StreamContext->IsDirty = FALSE;

    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);


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
        FltFreePoolAlignedWithTag(Instance, WriteBuffer, WRITE_BUFFER_TAG);
        WriteBuffer = NULL;
    }

    return Status;
}


NTSTATUS PocNtfsFlushAndPurgeCache(
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject)
{
    if (NULL == Instance)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Instance is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == FileObject)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileObject is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PFLT_CALLBACK_DATA Data = NULL;

    Status = FltAllocateCallbackData(Instance, FileObject, &Data);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocNtfsFlushAndPurgeCache->FltAllocateCallbackData failed. Status = 0x%x\n", Status));
        return Status;
    }

    Data->Iopb->MajorFunction = IRP_MJ_FLUSH_BUFFERS;
    Data->Iopb->MinorFunction = IRP_MN_FLUSH_AND_PURGE;
    Data->Iopb->IrpFlags = IRP_SYNCHRONOUS_API;
    FltPerformSynchronousIo(Data);
    
    FltFreeCallbackData(Data);

    return Data->IoStatus.Status;
}


NTSTATUS PocFlushOriginalCache(
    IN PFLT_INSTANCE Instance,
    IN PWCHAR FileName)
{
    if (NULL == Instance)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Instance is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileName is NULL.\n", __FUNCTION__));
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
        Instance,
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltCreateFileEx failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    if (CcIsFileCached(FileObject))
    {
        Status = FltFlushBuffers(Instance, FileObject);

        if (STATUS_SUCCESS != Status)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocFlushOriginalCache->FltFlushBuffers failed. Status = 0x%x\n", Status));
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReentryToGetStreamContext->FileName is NULL.\n"));
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReentryToGetStreamContext->ZwCreateFile failed. Status = 0x%x\n", Status));
        goto EXIT;
    }

    Status = ObReferenceObjectByHandle(hFile, STANDARD_RIGHTS_ALL, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReentryToGetStreamContext->ObReferenceObjectByHandle failed ststus = 0x%x.\n", Status));
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReentryToGetStreamContext->PocFindOrCreateStreamContext failed. Status = 0x%x\n", Status));
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileName is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PPOC_STREAM_CONTEXT StreamContext = NULL;

    LONGLONG FileSize = 0;
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
        if (STATUS_NOT_FOUND == Status)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReentryToGetStreamContext failed. Irrelevent file extension\n", __FUNCTION__));
            Status = POC_IRRELEVENT_FILE_EXTENSION;
        }
        else
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReentryToGetStreamContext failed. Status = 0x%x FileName = %ws\n", 
                __FUNCTION__, Status, FileName));
        }
        goto EXIT;
    }

    if (TRUE == StreamContext->IsCipherText)
    {
        Status = POC_FILE_IS_CIPHERTEXT;

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
            ("%s->%ws is ciphertext. Encrypt failed. FileSize = %I64d.\n",
            __FUNCTION__, FileName, StreamContext->FileSize));

        goto EXIT;
    }

    if(POC_RENAME_TO_ENCRYPT == StreamContext->Flag)
    {
        Status = STATUS_SUCCESS;
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
            ("%s->%ws being rename to encrypt. Encrypt success.\n", __FUNCTION__, FileName));
        goto EXIT;
    }


    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(
        &ObjectAttributes, 
        &uFileName, 
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 
        NULL, 
        NULL);

    /*
    * 这里不能用FltCreateFile，因为它建的FileObject是非重入的，在这个FileObject上建立的缓冲也是非重入的，
    * 我们的PreWrite无法加密后面PocWriteFileIntoCache写入的数据。
    * 如果一个大文件，在特权加密之前并没有建立缓冲，那么这里就会出现上述情况，特权加密实际上是失败的。
    */

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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ZwCreateFile failed. Status = 0x%x\n", __FUNCTION__, Status));
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ObReferenceObjectByHandle failed. Status = 0x%x.\n", __FUNCTION__, Status));
        goto EXIT;
    }

    /*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\n %s->Process = %p Thread = %p Fcb = %p Ccb = %p Resource = %p PagingIoResource = %p.\n\n",
        __FUNCTION__,
        PsGetCurrentProcess(),
        PsGetCurrentThread(),
        (PCHAR)FileObject->FsContext,
        FileObject->FsContext2,
        ((PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext)->Resource,
        ((PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext)->PagingIoResource));*/

    FileSize = PocQueryEndOfFileInfo(Instance, FileObject);

    if(0 == FileSize)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileSize is zero.\n", __FUNCTION__));
        Status = STATUS_SUCCESS;
        goto EXIT;
    }

    ReadBuffer = ExAllocatePoolWithTag(PagedPool, FileSize, READ_BUFFER_TAG);

    if (NULL == ReadBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag ReadBuffer failed.\n", __FUNCTION__));
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
        (ULONG)FileSize);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReadFileFromCache failed. Status = 0x%x\n", __FUNCTION__, Status));
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ZwCreateFile failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    PocUpdateFlagInStreamContext(StreamContext, 0);

    Status = ObReferenceObjectByHandle(
        hFile, 
        STANDARD_RIGHTS_ALL, 
        *IoFileObjectType, 
        KernelMode, 
        (PVOID*)&FileObject, 
        NULL);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ObReferenceObjectByHandle failed. Status = 0x%x.\n", __FUNCTION__, Status));
        goto EXIT;
    }


    ByteOffset.QuadPart = 0;

    /*
    * 这里不能用FltWriteFileEx，因为它的缓冲写是非重入的，16个字节以内的文件
    * 我们需要缓冲写操作重入到minifilter中去扩展文件大小。
    */
    ZwWriteFile(
        hFile, 
        NULL, 
        NULL, 
        NULL, 
        &IoStatusBlock, 
        ReadBuffer, 
        (ULONG)FileSize, 
        &ByteOffset, 
        NULL);


    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ZwWriteFile failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\n%s->success. FileName = %ws FileSize = %I64d.\n",
        __FUNCTION__,
        FileName,
        ((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->FileSize.QuadPart));

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
        ZwClose(hFile);
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileName is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PPOC_STREAM_CONTEXT StreamContext = NULL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    LONGLONG FileSize = 0;
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
        if (STATUS_NOT_FOUND == Status)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReentryToGetStreamContext failed. Irrelevent file extension\n", __FUNCTION__));
            Status = POC_IRRELEVENT_FILE_EXTENSION;
        }
        else
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReentryToGetStreamContext failed. Status = 0x%x\n", __FUNCTION__, Status));
        }
        goto EXIT;
    }

    if (FALSE == StreamContext->IsCipherText)
    {
        Status = POC_FILE_IS_PLAINTEXT;
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->%ws is plaintext. Decrypt failed.\n", __FUNCTION__, FileName));
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ZwCreateFile failed. Status = 0x%x\n", __FUNCTION__, Status));
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ObReferenceObjectByHandle failed. Status = 0x%x.\n", __FUNCTION__, Status));
        goto EXIT;
    }

    if (FileObject->SectionObjectPointer == StreamContext->ShadowSectionObjectPointers)
    {
        if (TRUE == StreamContext->IsReEncrypted)
        {
            /*
            * PrivateCacheMap要置0，否则文件系统驱动不建立缓冲，不过这里不会进入了，
            * 因为在PostCreate对这个状态的文件，无论是什么进程，都指向明文缓冲。
            */
            FileObject->SectionObjectPointer = StreamContext->OriginSectionObjectPointers;
            FileObject->PrivateCacheMap = NULL;
        }
        else
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Unauthorized process can't decrypt file.\n", __FUNCTION__));
            Status = POC_IS_UNAUTHORIZED_PROCESS;
            goto EXIT;
        }
    }

    FileSize = StreamContext->FileSize;

    ReadBuffer = ExAllocatePoolWithTag(PagedPool, FileSize, READ_BUFFER_TAG);

    if (NULL == ReadBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag ReadBuffer failed.\n", __FUNCTION__));
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
        (ULONG)FileSize);


    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReadFileFromCache failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }


    Status = PocSetEndOfFileInfo(
        Instance,
        FileObject,
        FileSize);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocSetEndOfFileInfo failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    if (NULL != hFile)
    {
        ZwClose(hFile);
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltCreateFileEx failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }


    WriteLength = ROUND_TO_PAGES(FileSize);

    WriteBuffer= FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, WriteLength, WRITE_BUFFER_TAG);

    if (NULL == WriteBuffer)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltAllocatePoolAlignedWithTag WriteBuffer failed.\n", __FUNCTION__));
        Status = STATUS_INSUFFICIENT_RESOURCES;
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltWriteFileEx failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->success. FileName = %ws FileSize = %I64d.\n\n",
        __FUNCTION__,
        FileName,
        ((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->FileSize.QuadPart));

    PocUpdateFlagInStreamContext(StreamContext, 0);

    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

    StreamContext->IsCipherText = FALSE;
    StreamContext->FileSize = 0;
    RtlZeroMemory(StreamContext->FileName, POC_MAX_NAME_LENGTH * sizeof(WCHAR));

    StreamContext->IsReEncrypted = FALSE;

    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);
    

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


VOID PocAppendEncTailerThread(
    IN PVOID StartContext)
{
    PPOC_STREAM_CONTEXT StreamContext = StartContext;

    if (NULL == StreamContext ||
        NULL == StreamContext->FileName ||
        NULL == StreamContext->Volume ||
        NULL == StreamContext->Instance)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
            ("%s->StreamContext or FileName or Volume or Instance is NULL.\n", __FUNCTION__));
        return;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    LARGE_INTEGER Interval = { 0 };
    Interval.QuadPart = -30 * 1000 * 1000; //3s

    BOOLEAN Continue = 0;

    /*
    * 这里要遍历一下判断操作该文件的所有授权进程已关闭，
    * 此时可以重入加密或写入文件标识尾，不会有死锁了。
    */
    while (TRUE)
    {

        Continue = FALSE;

        Status = KeDelayExecutionThread(KernelMode, FALSE, &Interval);


        for (ULONG i = 0; i < POC_MAX_AUTHORIZED_PROCESS_COUNT; i++)
        {
            if (NULL != StreamContext->ProcessId[i])
            {
                
                /*
                * 遍历一下链表，如果进程结束，
                * 链表节点会在PocProcessNotifyRoutineEx函数中被清除掉。
                */
                Status = PocFindProcessInfoNodeByPidEx(
                    StreamContext->ProcessId[i],
                    NULL,
                    FALSE,
                    FALSE);

                if (STATUS_SUCCESS != Status)
                {
                    StreamContext->ProcessId[i] = NULL;
                }
                else
                {
                    Continue = TRUE;
                }
            }
        }

        if (!Continue)
        {
            break;
        }

    }


    /*
    * 添加加密标识尾的地方
    * 或者如果加密标识尾内的FileName错了，PostClose更新一下
    * （之所以错误是因为对文件进行了重命名操作）
    * POC_TO_APPEND_ENCRYPTION_TAILER是在PreWrite设置的
    * POC_TAILER_WRONG_FILE_NAME是在PostCreate设置的
    * POC_RENAME_TO_ENCRYPT是在PostSetInfo设置的，针对的是tmp文件重命名为目标扩展文件的情况
    */

    ExAcquireResourceSharedLite(StreamContext->Resource, TRUE);

    if ((POC_TO_APPEND_ENCRYPTION_TAILER == StreamContext->Flag ||
        POC_TAILER_WRONG_FILE_NAME == StreamContext->Flag) &&
        StreamContext->AppendTailerThreadStart)
    {
        ExReleaseResourceLite(StreamContext->Resource);

        PocUpdateFlagInStreamContext(StreamContext, POC_BEING_APPEND_ENC_TAILER);

        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

        StreamContext->AppendTailerThreadStart = FALSE;

        ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);


        Status = PocAppendEncTailerToFile(StreamContext->Volume, StreamContext->Instance, StreamContext);

        if (STATUS_SUCCESS != Status)
        {
            PocUpdateFlagInStreamContext(StreamContext, POC_TO_APPEND_ENCRYPTION_TAILER);
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocAppendEncTailerToFile failed. Status = 0x%x. FileName = %ws .\n",
                __FUNCTION__,
                Status,
                StreamContext->FileName));

            Status = FLT_POSTOP_FINISHED_PROCESSING;
            goto EXIT;
        }

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\n%s->Append tailer success. FileName = %ws.\n\n",
            __FUNCTION__,
            StreamContext->FileName));

        PocUpdateFlagInStreamContext(StreamContext, POC_FILE_HAS_ENCRYPTION_TAILER);

    }
    else if (POC_RENAME_TO_ENCRYPT == StreamContext->Flag &&
        StreamContext->AppendTailerThreadStart)
    {
        ExReleaseResourceLite(StreamContext->Resource);

        PocUpdateFlagInStreamContext(StreamContext, POC_BEING_DIRECT_ENCRYPTING);

        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

        StreamContext->AppendTailerThreadStart = FALSE;

        ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

        /*
        * 其他类型文件重命名为目标扩展文件的情况，对重命名的文件进行加密
        * 这个POC_RENAME_TO_ENCRYPT是在PostSetInformation中设置的。
        */
        Status = PocReentryToEncrypt(StreamContext->Instance, StreamContext->FileName);

        if (STATUS_SUCCESS != Status && POC_FILE_IS_CIPHERTEXT != Status)
        {
            PocUpdateFlagInStreamContext(StreamContext, POC_RENAME_TO_ENCRYPT);
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReentryToEncrypt failed. Status = 0x%x.\n",
                __FUNCTION__,
                Status));

            Status = FLT_POSTOP_FINISHED_PROCESSING;
            goto EXIT;
        }

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\n%s->PocReentryToEncrypt success. FileName = %ws.\n\n",
            __FUNCTION__,
            StreamContext->FileName));
    }
    else if (POC_TO_DECRYPT_FILE == StreamContext->Flag &&
        StreamContext->AppendTailerThreadStart)
    {
        ExReleaseResourceLite(StreamContext->Resource);

        PocUpdateFlagInStreamContext(StreamContext, POC_BEING_DECRYPT_FILE);

        ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

        StreamContext->AppendTailerThreadStart = FALSE;

        ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

        Status = PocReentryToDecrypt(StreamContext->Instance, StreamContext->FileName);

        if (STATUS_SUCCESS != Status)
        {
            PocUpdateFlagInStreamContext(StreamContext, POC_TO_DECRYPT_FILE);
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocReentryToDecrypt failed. Status = 0x%x.\n",
                __FUNCTION__,
                Status));

            Status = FLT_POSTOP_FINISHED_PROCESSING;
            goto EXIT;
        }

        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\n%s->PocReentryToDecrypt success.\n\n",
            __FUNCTION__));
    }
    else
    {
        ExReleaseResourceLite(StreamContext->Resource);
    }


EXIT:

    ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

    StreamContext->AppendTailerThreadStart = FALSE;

    ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    PsTerminateSystemThread(Status);
}


NTSTATUS PocInitFlushFileObject(
    IN PWCHAR FileName,
    IN OUT PFILE_OBJECT* FileObject)
{

    if (NULL == FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileName is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };


    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwCreateFile(
        &hFile,
        0,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ZwCreateFile failed. Status = 0x%x\n", __FUNCTION__, Status));
        goto EXIT;
    }

    Status = ObReferenceObjectByHandle(
        hFile,
        STANDARD_RIGHTS_ALL,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)FileObject,
        NULL);

    if (STATUS_SUCCESS != Status)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ObReferenceObjectByHandle failed. Status = 0x%x.\n", __FUNCTION__, Status));
        goto EXIT;
    }


EXIT:

    if (NULL != hFile)
    {
        FltClose(hFile);
        hFile = NULL;
    }

    return Status;
}


NTSTATUS PocFindOrCreateStreamContextOutsite(
    IN PFLT_INSTANCE Instance,
    IN PWCHAR FileName,
    IN BOOLEAN CreateIfNotFound)
{
    if (NULL == Instance)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Instance is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    if (NULL == FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileName is NULL.\n", __FUNCTION__));
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING uFileName = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    HANDLE hFile = NULL;
    PFILE_OBJECT FileObject = NULL;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    PPOC_STREAM_CONTEXT StreamContext = NULL;
    BOOLEAN ContextCreated = FALSE;


    RtlInitUnicodeString(&uFileName, FileName);

    InitializeObjectAttributes(&ObjectAttributes, &uFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = FltCreateFileEx(
        gFilterHandle,
        Instance,
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
        //PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltCreateFileEx failed. Status = 0x%x. FileName = %ws.\n", __FUNCTION__, Status, FileName));
        goto EXIT;
    }

    Status = PocFindOrCreateStreamContext(
        Instance,
        FileObject,
        CreateIfNotFound,
        &StreamContext,
        &ContextCreated);

    if (STATUS_SUCCESS != Status)
    {
        if (CreateIfNotFound)
        {
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocFindOrCreateStreamContext failed. Status = 0x%x.\n",
                __FUNCTION__, Status));
        }
        goto EXIT;
    }

    Status = STATUS_SUCCESS;

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

    if (NULL != StreamContext)
    {
        FltReleaseContext(StreamContext);
        StreamContext = NULL;
    }

    return Status;
}


VOID PocPurgeCache(
    IN PWCHAR FileName,
    IN PFLT_INSTANCE Instance,
    IN PSECTION_OBJECT_POINTERS SectionObjectPointers)
{
    if (NULL == FileName)
    {
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FileName is NULL.\n", __FUNCTION__));
        return;
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
        Instance,
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
        PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocReadFileNoCache->FltCreateFileEx failed. Status = 0x%x\n", Status));
        goto EXIT;
    }

    ExEnterCriticalRegionAndAcquireResourceExclusive(((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->Resource);

    CcPurgeCacheSection(SectionObjectPointers, NULL, 0, FALSE);

    ExReleaseResourceAndLeaveCriticalRegion(((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->Resource);

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

}
