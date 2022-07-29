
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




/**
 * @Author: wangzhankun
 * @Date: 2022-06-21 15:29:06
 * @LastEditors: wangzhankun
 * @update:
 * @brief 判断 encryption_tailer 究竟是不是 encryption_tailer
 * @param {PPOC_ENCRYPTION_TAILER} encryption_tailer
 * @return true if it is encryption_tailer, false otherwise
 */
BOOLEAN PocIsAppendEncryptionTailer(PPOC_ENCRYPTION_TAILER encryption_tailer)
{
    BOOLEAN true_encryption_tailer_bool = TRUE;
    for (int i = 0; i < sizeof(EncryptionTailer.Flag); i++)
    {
        if (encryption_tailer->Flag[i] != EncryptionTailer.Flag[i])
        {
            true_encryption_tailer_bool = FALSE;
            break;
        }
    }
    if (strcmp(encryption_tailer->EncryptionAlgorithmType, EncryptionTailer.EncryptionAlgorithmType) != 0)
    {
        true_encryption_tailer_bool = FALSE;
    }
    return true_encryption_tailer_bool;
}

/**
 * @Author: wangzhankun
 * @Date: 2022-06-24 11:07:28
 * @LastEditors: wangzhankun
 * @update:
 * @brief 通过以非重入的形式读取文件标识尾判断文件是否有文件标识尾。如果有的话，返回值是 STATUS_SUCCESS。
 * 该函数运行在 <= APC_LEVEL 级别。不能在PreCreate中调用，因为此时FileObject还未打开。
 * @param [in] {IN PFLT_INSTANCE} Instance
 * @param [in] {PWCHAR} FileObject 已经打开的文件对象。该对象最早是在PostCreate中可以获取到。
 * @return NTSTATUS STATUS_SUCCESS if it is encryption_tailer
 */
NTSTATUS PocIsFileUnderControl(_In_ PFLT_INSTANCE Instance,
                               _In_ PFILE_OBJECT FileObject)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCHAR read_buffer = NULL;
    const int BUFFER_SIZE = 2 * PAGE_SIZE;
    __try
    {

        ULONG volume_sector_size = 0;
        { //获取volume_sector_size
            Status = PocGetVolumeSectorSize(Instance, &volume_sector_size);
            if (!NT_SUCCESS(Status))
            {
                // PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d PocGetVolumeSectorSize failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
                __leave;
            }
        }

        LARGE_INTEGER file_size = {0}; // in bytes
        {                              // 获取文件大小
            FILE_STANDARD_INFORMATION info;
            Status = FltQueryInformationFile(
                Instance,
                FileObject,
                &info,
                sizeof(info),
                FileStandardInformation,
                NULL);
            if (!NT_SUCCESS(Status))
            {
                // PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d FltQueryInformationFile failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
                __leave;
            }
            file_size = info.EndOfFile; // 当前的文件大小可能包含了文件标识尾
            if (file_size.QuadPart < PAGE_SIZE)
            {
                Status = STATUS_NOT_FOUND;
                __leave;
            }
        }

        { // 分配内存
            read_buffer = (PCHAR)FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, BUFFER_SIZE, READ_BUFFER_TAG);
            if (read_buffer == NULL)
            {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                // PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d FltAllocatePoolAlignedWithTag failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
                __leave;
            }
        }

        PPOC_ENCRYPTION_TAILER encryption_tailer = NULL;
        { //读取文件标识尾
            PCHAR encryption_tailer_buffer = read_buffer;

            {
                LARGE_INTEGER byteOffset = {0};
                ULONG bytesRead = 0;

                byteOffset.QuadPart = file_size.QuadPart - PAGE_SIZE;

                // 这里需要对byteOffset进行对齐

                byteOffset.QuadPart = ROUND_TO_SIZE(byteOffset.QuadPart, volume_sector_size);

                Status = FltReadFile(
                    Instance,
                    FileObject,
                    &byteOffset, //不会被自动更新
                    PAGE_SIZE,
                    encryption_tailer_buffer,
                    FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                    &bytesRead, // A pointer to a caller-allocated variable that receives the number of bytes read from the file.
                    NULL,
                    NULL);

                if (!NT_SUCCESS(Status))
                {
                    // PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d FltReadFileEx failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
                    __leave;
                }

                if (PocIsAppendEncryptionTailer((PPOC_ENCRYPTION_TAILER)encryption_tailer_buffer))
                {
                    encryption_tailer = (PPOC_ENCRYPTION_TAILER)encryption_tailer_buffer;
                }
            }
        }

        if (encryption_tailer == NULL)
        {
            Status = STATUS_NOT_FOUND;
        }
        else
        {
            Status = STATUS_SUCCESS;
        }
    }
    __finally
    {
        if (read_buffer != NULL)
        {
            FltFreePoolAlignedWithTag(Instance, read_buffer, READ_BUFFER_TAG);
        }
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
