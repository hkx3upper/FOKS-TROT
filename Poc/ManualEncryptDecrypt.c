
#include "manualencryptdecrypt.h"
#include "filefuncs.h"
#include "utils.h"
#include "cipher.h"
#include "context.h"
#include "fileobject.h"

#define MANUAL_ENCRYPT_DECRYPT_BUFFER_TAG 'medb'







/**
 * @Author: wangzhankun
 * @Date: 2022-06-20 12:54:05
 * @LastEditors: wangzhankun
 * @update:
 * @brief 以非重入、无缓存的方式对文件进行加密和解密
 * @param {PWCHAR} _FileName 需要进行手动加解密的文件名
 * @param {IN PFLT_INSTANCE} Instance 实例
 * @param {BOOLEAN} is_for_encrypt true for encrypt, false for decrypt
 * @return NTSTATUS
 */
NTSTATUS PocManualEncryptOrDecrypt(const PWCHAR _FileName, IN PFLT_INSTANCE Instance, const BOOLEAN is_for_encrypt)
{
	NTSTATUS Status = STATUS_SUCCESS;
	const ULONG BUFFER_SIZE = 64 * 1024 * PAGE_SIZE; // 64 * 4MB // PAGE_SIZE 是 4KB
	PCHAR read_buffer = NULL, write_buffer = NULL;
	HANDLE hFile = NULL;
	PFILE_OBJECT FileObject = NULL;

	WCHAR FileName[POC_MAX_NAME_LENGTH];
	{
		Status = PocAnyPath2DosPath(_FileName, FileName, POC_MAX_NAME_LENGTH);
		if (!NT_SUCCESS(Status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d PocAnyPath2DosPath failed, Status: 0x%08x\n", __FUNCTION__, __FILE__, __LINE__, Status));
			return Status;
		}
	}

	ULONG volume_sector_size = 0;
	Status = PocGetVolumeSectorSize(Instance, &volume_sector_size);
	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d PocGetVolumeSectorSize failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
		return Status;
	}

	PCHAR encryption_tailer_buffer = NULL;

	__try
	{
		OBJECT_ATTRIBUTES ObjectAttributes = {0};
		IO_STATUS_BLOCK IoStatusBlock = {0};
		UNICODE_STRING uFileName;
		{ //打开文件
			RtlInitUnicodeString(&uFileName, FileName);
			InitializeObjectAttributes(&ObjectAttributes,
									   &uFileName,
									   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
									   NULL,
									   NULL);

			Status = FltCreateFileEx(
				gFilterHandle,
				Instance,
				&hFile,
				&FileObject,
				GENERIC_READ | GENERIC_WRITE,
				&ObjectAttributes,
				&IoStatusBlock,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				0, //独占模式
				FILE_OPEN,
				FILE_NON_DIRECTORY_FILE |
					FILE_SEQUENTIAL_ONLY |
					FILE_NO_INTERMEDIATE_BUFFERING,
				NULL,
				0,
				IO_FORCE_ACCESS_CHECK);
			if (!NT_SUCCESS(Status))
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d FltCreateFileEx failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
				__leave;
			}
		}

		{ // 分配内存
			read_buffer = (PCHAR)FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, BUFFER_SIZE, MANUAL_ENCRYPT_DECRYPT_BUFFER_TAG);
			if (read_buffer == NULL)
			{
				Status = STATUS_INSUFFICIENT_RESOURCES;
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d FltAllocatePoolAlignedWithTag failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
				__leave;
			}

			write_buffer = (PCHAR)FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, BUFFER_SIZE, MANUAL_ENCRYPT_DECRYPT_BUFFER_TAG);
			if (write_buffer == NULL)
			{
				Status = STATUS_INSUFFICIENT_RESOURCES;
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d FltAllocatePoolAlignedWithTag failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
				__leave;
			}

			encryption_tailer_buffer = (PCHAR)FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, PAGE_SIZE, MANUAL_ENCRYPT_DECRYPT_BUFFER_TAG);
			if (encryption_tailer_buffer == NULL)
			{
				Status = STATUS_INSUFFICIENT_RESOURCES;
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d FltAllocatePoolAlignedWithTag failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
				__leave;
			}
		}

		LARGE_INTEGER file_size = {0}; // in bytes
		{							   // 获取文件大小
			FILE_STANDARD_INFORMATION info;
			Status = FltQueryInformationFile(
				Instance,
				FileObject,
				&info,
				sizeof(info),
				FileStandardInformation,
				NULL);
			file_size = info.EndOfFile; // 当前的文件大小可能包含了文件标识尾
		}

		PPOC_ENCRYPTION_TAILER encryption_tailer = NULL;
		{ // 读取文件标识尾，如果有的话

			// 判断文件大小，如果大于等于文件标识尾的大小，则尝试读取文件标识尾，如果存在文件标识尾，则判断当前文件的文件状态是否是已加密的
			// 另外需要对重命名等情况进行考虑

			if (file_size.QuadPart > PAGE_SIZE)
			{
				LARGE_INTEGER byteOffset = {0};
				ULONG bytesRead = 0;

				byteOffset.QuadPart = file_size.QuadPart - PAGE_SIZE;

				// 这里需要对byteOffset进行对齐

				byteOffset.QuadPart = ROUND_TO_SIZE(byteOffset.QuadPart, volume_sector_size);

				Status = FltReadFileEx(
					Instance,
					FileObject,
					&byteOffset, //会被自动更新
					PAGE_SIZE,
					encryption_tailer_buffer,
					FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
					&bytesRead, // A pointer to a caller-allocated variable that receives the number of bytes read from the file.
					NULL,
					NULL,
					NULL,
					NULL);

				if (!NT_SUCCESS(Status))
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d FltReadFileEx failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
					__leave;
				}

				if (PocIsAppendEncryptionTailer((PPOC_ENCRYPTION_TAILER)encryption_tailer_buffer))
				{
					encryption_tailer = (PPOC_ENCRYPTION_TAILER)encryption_tailer_buffer;
				}
			}

			if (encryption_tailer)
			{
				file_size.QuadPart = encryption_tailer->FileSize; // 保证 file_size 就是实际内容的大小
			}

			if (is_for_encrypt)
			{ //对文件进行加密
				if (encryption_tailer && encryption_tailer->IsCipherText)
				{
					// 已经是加密好的文件就不需要加密了
					Status = STATUS_SUCCESS; // TODO 优化返回值
					__leave;
				}
				if (!encryption_tailer)
				{
					// 没有文件标识尾则认为是明文，需要创建文件标识尾
					encryption_tailer = (PPOC_ENCRYPTION_TAILER)encryption_tailer_buffer;
					RtlZeroBytes(encryption_tailer, PAGE_SIZE);
				}
				// 对于有文件标识尾且文件状态为未加密的文件，不需要特殊处理

				if (encryption_tailer)
				{
					RtlCopyBytes(encryption_tailer, &EncryptionTailer, sizeof(EncryptionTailer));
					encryption_tailer->IsCipherText = is_for_encrypt;
					encryption_tailer->FileSize = file_size.QuadPart;
					RtlCopyMemory(encryption_tailer->FileName, FileName, wcslen(FileName) * sizeof(WCHAR));
				}
			}
			else
			{ //对文件进行解密
				if (!encryption_tailer || !(encryption_tailer->IsCipherText))
				{
					// 没有文件标识尾或者已经是解密好的文件就不需要解密了
					Status = STATUS_SUCCESS; // TODO 优化返回值
					__leave;
				}
				// 有文件标识尾，且处于密文状态的文件才需要进行解密
			}
		}

		// 到目前位置可以保证 file_size 是实际内容的大小，file_size == encryption_tailer->FileSize
		ASSERT(file_size.QuadPart == encryption_tailer->FileSize);

		LARGE_INTEGER byteOffset = {0}; //写入文件标识尾的时候需要用到
		ULONG bytesRead = 0;
		ULONG bytesWrite = 0;

		{ //读取文件并加密/解密写入

			while (TRUE)
			{
				byteOffset.QuadPart += bytesRead; //这里不需要对齐SECTOR_SIZE，每次读取BUFFER_SIZE大小的数据，暗含已经对齐了

				if (byteOffset.QuadPart >= file_size.QuadPart)
				{
					break; //为了保证 byteOffset 能够顺利的被更新，只能在这里 break
				}

				{ //读取数据
					Status = FltReadFileEx(
						Instance,
						FileObject,
						&byteOffset, //不会被自动更新
						BUFFER_SIZE,
						read_buffer,
						FLTFL_IO_OPERATION_NON_CACHED |
							FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
						&bytesRead, // A pointer to a caller-allocated variable that receives the number of bytes read from the file.
						NULL,
						NULL,
						NULL,
						NULL);
					if (!NT_SUCCESS(Status))
					{
						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d FltReadFile failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
						__leave;
					}
					if (byteOffset.QuadPart + bytesRead > file_size.QuadPart)
					{ //这样就能保证读取到的内容一定是实际内容，而不会误读入文件标识尾
						bytesRead = (ULONG)(file_size.QuadPart - byteOffset.QuadPart);
					}
				}

				{ //为方便密文挪用，这里进行数据截取
					LARGE_INTEGER left;
					left.QuadPart = file_size.QuadPart - byteOffset.QuadPart - bytesRead;

					if (left.QuadPart < AES_BLOCK_SIZE && left.QuadPart > 0)
					{
						// 如果剩下的数据不足一个AES_BLOCK_SIZE，就需要密文挪用
						bytesRead -= PAGE_SIZE; //密文挪用只需要减去一个AES_BLOCK_SIZE即可，这里减去1个页面大小是为了与sector size对齐
												// 另外既然剩下还有一些数据未读取，那么当前bytesRead == BUFFER_SIZE，无需担心不够减的情况
					}
				}

				{							  //加密 or 解密
					bytesWrite = BUFFER_SIZE; //需要设置为缓冲区的大小。

					if (is_for_encrypt)
					{
						Status = PocManualEncrypt(read_buffer, bytesRead, write_buffer, &bytesWrite, file_size.QuadPart);
						if (!NT_SUCCESS(Status))
						{
							PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d PocManualEncrypt failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
							__leave;
						}

						bytesWrite = ROUND_TO_SIZE(bytesWrite, AES_BLOCK_SIZE);
					}
					else
					{
						// 由于此时 bytesRead 是根据 file_size 进行了截断

						Status = PocManualDecrypt(read_buffer, bytesRead, write_buffer, &bytesWrite, file_size.QuadPart);
						if (!NT_SUCCESS(Status))
						{
							PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d PocManualDecrypt failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
							__leave;
						}
					}
				}

				{ //写入数据
					bytesWrite = ROUND_TO_SIZE(bytesWrite, volume_sector_size);
					Status = FltWriteFileEx(
						Instance,
						FileObject,
						&byteOffset,
						bytesWrite,
						write_buffer,
						FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
						&bytesWrite,
						NULL,
						NULL,
						NULL,
						NULL);

					if (!NT_SUCCESS(Status))
					{
						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d FltWriteFile failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
						__leave;
					}
				}
			}
		}

		{ // 写入文件标识尾
			//解密的话就不写入文件标识尾了
			if (is_for_encrypt)
			{
				byteOffset.QuadPart = ROUND_TO_SIZE(byteOffset.QuadPart, volume_sector_size);

				Status = FltWriteFileEx(
					Instance,
					FileObject,
					&byteOffset,
					PAGE_SIZE,
					encryption_tailer_buffer,
					FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
					&bytesWrite,
					NULL,
					NULL,
					NULL,
					NULL);
				if (!NT_SUCCESS(Status))
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d FltWriteFile failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
					__leave;
				}
			}
			else
			{
				// 解密的时候需要重设文件大小。截断文件标识尾等数据
				FILE_END_OF_FILE_INFORMATION info;
				info.EndOfFile.QuadPart = encryption_tailer->FileSize;
				Status = FltSetInformationFile(Instance,
											   FileObject,
											   &info,
											   sizeof(info),
											   FileEndOfFileInformation);
				if (STATUS_SUCCESS != Status)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d FltSetInformationFile failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
					__leave;
				}
			}
		}

		{
			//这里使用了new_status，因为这边发生错误的话，是不影响文件的加密或者解密
			NTSTATUS new_status = Status;

			// if (!is_for_encrypt)
			{
				PPOC_STREAM_CONTEXT stream_context = NULL;
				__try
				{
					new_status = PocFindOrCreateStreamContext(Instance, FileObject, FALSE, &stream_context, NULL);
					if (new_status != STATUS_SUCCESS)
					{
						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d PocFindOrCreateStreamContext failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, new_status));
						__leave;
					}
					if (stream_context)
					{
						ExEnterCriticalRegionAndAcquireResourceExclusive(stream_context->Resource);
						stream_context->IsCipherText = is_for_encrypt;
						ExReleaseResourceAndLeaveCriticalRegion(stream_context->Resource);
					}
				}
				__finally
				{
				}
			}
		}
	}
	__finally
	{

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

		if (read_buffer)
		{
			FltFreePoolAlignedWithTag(Instance, read_buffer, MANUAL_ENCRYPT_DECRYPT_BUFFER_TAG);
		}

		if (write_buffer)
		{
			FltFreePoolAlignedWithTag(Instance, write_buffer, MANUAL_ENCRYPT_DECRYPT_BUFFER_TAG);
		}

		if (encryption_tailer_buffer)
		{
			FltFreePoolAlignedWithTag(Instance, encryption_tailer_buffer, MANUAL_ENCRYPT_DECRYPT_BUFFER_TAG);
		}
	}

	return Status;
}
