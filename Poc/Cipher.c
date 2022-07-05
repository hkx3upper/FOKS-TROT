

#include "cipher.h"
#include "global.h"

AES_INIT_VARIABLES AesInitVar;


NTSTATUS PocInitAesECBKey()
/*
* 加密算法的初始化，AES-128 ECB模式，密钥是rgbAES128Key
*/
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ULONG cbData = 0, cbKeyObject = 0;

	UCHAR rgbAES128Key[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};

	RtlZeroMemory(&AesInitVar, sizeof(AES_INIT_VARIABLES));

	Status = BCryptOpenAlgorithmProvider(&AesInitVar.hAesAlg, BCRYPT_AES_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitAesECBKey->BCryptOpenAlgorithmProvider failed. Status = 0x%x.\n", Status));
		goto ERROR;
	}
	
	Status = BCryptGetProperty(AesInitVar.hAesAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(ULONG), &cbData, 0);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitAesECBKey->BCryptGetProperty failed. Status = 0x%x.\n", Status));
		goto ERROR;
	}

	AesInitVar.pbKeyObject = ExAllocatePoolWithTag(NonPagedPool, cbKeyObject, KEY_OBJECT_BUFFER);

	if (NULL == AesInitVar.pbKeyObject)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitAesECBKey->ExAllocatePoolWithTag pbKeyObject failed.\n"));
		goto ERROR;
	}

	Status = BCryptSetProperty(AesInitVar.hAesAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitAesECBKey->BCryptSetProperty failed. Status = 0x%x.\n", Status));
		goto ERROR;
	}

	Status = BCryptGenerateSymmetricKey(AesInitVar.hAesAlg, &AesInitVar.hKey, AesInitVar.pbKeyObject, cbKeyObject, rgbAES128Key, sizeof(rgbAES128Key), 0);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitAesECBKey->BCryptGenerateSymmetricKey failed. Status = 0x%x.\n", Status));
		goto ERROR;
	}

	Status = STATUS_SUCCESS;
	AesInitVar.Flag = TRUE;
	goto EXIT;

ERROR:

	if (NULL != AesInitVar.hKey)
	{
		BCryptDestroyKey(AesInitVar.hKey);
		AesInitVar.hKey = NULL;
	}

	if (NULL != AesInitVar.pbKeyObject)
	{
		ExFreePoolWithTag(AesInitVar.pbKeyObject, KEY_OBJECT_BUFFER);
		AesInitVar.pbKeyObject = NULL;
	}

	if (NULL != AesInitVar.hAesAlg)
	{
		BCryptCloseAlgorithmProvider(AesInitVar.hAesAlg, 0);
		AesInitVar.hAesAlg = 0;
	}

	AesInitVar.Flag = FALSE;


EXIT:

	return Status;
}


VOID PocAesCleanup()
{
	if (!AesInitVar.Flag)
	{
		return;
	}

	if (NULL != AesInitVar.hKey)
	{
		BCryptDestroyKey(AesInitVar.hKey);
		AesInitVar.hKey = NULL;
	}

	if (NULL != AesInitVar.pbKeyObject)
	{
		ExFreePoolWithTag(AesInitVar.pbKeyObject, KEY_OBJECT_BUFFER);
		AesInitVar.pbKeyObject = NULL;
	}

	if (NULL != AesInitVar.hAesAlg)
	{
		BCryptCloseAlgorithmProvider(AesInitVar.hAesAlg, 0);
		AesInitVar.hAesAlg = NULL;
	}

	AesInitVar.Flag = FALSE;
}


NTSTATUS PocAesECBEncrypt(
	IN PCHAR InBuffer, 
	IN ULONG InBufferSize, 
	IN OUT PCHAR InOutBuffer, 
	IN OUT PULONG LengthReturned)
{
	//LengthReturned是复用的，在加密时，既作为InOutBuffer的内存大小输入，也作为加密后密文大小输出

	if (!AesInitVar.Flag)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt->AesInitVar.Flag = FALSE.\n"));
		return POC_STATUS_AES_INIT_FAILED;
	}

	if (NULL == InBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt->InBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == LengthReturned)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt->LengthReturned is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}


	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	

	Status = BCryptEncrypt(AesInitVar.hKey, (PUCHAR)InBuffer, InBufferSize,
		NULL, NULL, 0, (PUCHAR)InOutBuffer, *LengthReturned, LengthReturned, 0);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt->BCryptEncrypt encrypt plaintext failed. Status = 0x%x\n", Status));
	}

	return Status;
}


NTSTATUS PocAesECBDecrypt(
	IN PCHAR InBuffer, 
	IN ULONG InBufferSize, 
	IN OUT PCHAR InOutBuffer, 
	IN OUT PULONG LengthReturned)
{

	if (!AesInitVar.Flag)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt->AesInitVar.Flag = FALSE.\n"));
		return POC_STATUS_AES_INIT_FAILED;
	}

	if (NULL == InBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt->InBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == LengthReturned)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt->LengthReturned is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}


	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	Status = BCryptDecrypt(AesInitVar.hKey, (PUCHAR)InBuffer, (ULONG)InBufferSize,
		NULL, NULL, 0, (PUCHAR)InOutBuffer, *LengthReturned, LengthReturned, 0);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt->BCryptDecrypt decrypt ciphertext failed. Status = 0x%x\n", Status));
	}

	return Status;
}


NTSTATUS PocAesECBEncrypt_CiphertextStealing(
	IN PCHAR InBuffer, 
	IN ULONG InBufferSize, 
	IN OUT PCHAR InOutBuffer)
{
	if (!AesInitVar.Flag)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->AesInitVar.Flag = FALSE.\n"));
		return POC_STATUS_AES_INIT_FAILED;
	}

	if (NULL == InBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->InBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == InOutBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->InOutBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (InBufferSize % AES_BLOCK_SIZE == 0 || InBufferSize < AES_BLOCK_SIZE)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->Buffer is aligned with block size.\n"));
		return STATUS_UNSUCCESSFUL;
	}


	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ULONG TailLength = InBufferSize % AES_BLOCK_SIZE;
	ULONG LengthReturned = 0;
	ULONG Pn_1Offset = 0, PnOffset = 0;

	CHAR Pn[AES_BLOCK_SIZE] = { 0 };
	CHAR Cn_1[AES_BLOCK_SIZE] = { 0 };
	CHAR Cpadding[AES_BLOCK_SIZE] = { 0 };

	PCHAR AlignedBuffer = NULL;

	AlignedBuffer = ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)InBufferSize - (SIZE_T)TailLength, WRITE_BUFFER_TAG);

	if (NULL == AlignedBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->ExAllocatePoolWithTag AlignedBuffer failed.\\n"));
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}

	RtlZeroMemory(AlignedBuffer, InBufferSize - TailLength);

	RtlMoveMemory(AlignedBuffer, InBuffer, InBufferSize - TailLength);

	LengthReturned = InBufferSize - TailLength;
	Status = PocAesECBEncrypt(
		AlignedBuffer, 
		InBufferSize - TailLength, 
		InOutBuffer, 
		&LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->PocAesECBEncrypt1 failed. Status = 0x%x\n", Status));
		goto EXIT;
	}

	Pn_1Offset = InBufferSize - TailLength - AES_BLOCK_SIZE;
	PnOffset = Pn_1Offset + AES_BLOCK_SIZE;

	//InOutBuffer + Pn_1Offset == Cn
	RtlMoveMemory(InOutBuffer + PnOffset, InOutBuffer + Pn_1Offset, TailLength);

	RtlMoveMemory(Cpadding, InOutBuffer + Pn_1Offset + TailLength, AES_BLOCK_SIZE - TailLength);

	RtlZeroMemory(InOutBuffer + Pn_1Offset, AES_BLOCK_SIZE);

	

	RtlMoveMemory(Pn, InBuffer + PnOffset, TailLength);
	RtlMoveMemory(Pn + TailLength, Cpadding, AES_BLOCK_SIZE - TailLength);

	LengthReturned = AES_BLOCK_SIZE;
	Status = PocAesECBEncrypt(
		Pn,
		AES_BLOCK_SIZE,
		Cn_1,
		&LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBEncrypt_CiphertextStealing->PocAesECBEncrypt2 failed. Status = 0x%x\n", Status));
		goto EXIT;
	}

	RtlMoveMemory(InOutBuffer + Pn_1Offset, Cn_1, AES_BLOCK_SIZE);

	Status = STATUS_SUCCESS;

EXIT:

	if (NULL != AlignedBuffer)
	{
		ExFreePoolWithTag(AlignedBuffer, WRITE_BUFFER_TAG);
		AlignedBuffer = NULL;
	}

	return Status;
}


NTSTATUS PocAesECBDecrypt_CiphertextStealing(
	IN PCHAR InBuffer,
	IN ULONG InBufferSize,
	IN OUT PCHAR InOutBuffer)
{
	if (!AesInitVar.Flag)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->AesInitVar.Flag = FALSE.\n"));
		return POC_STATUS_AES_INIT_FAILED;
	}

	if (NULL == InBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->InBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == InOutBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->InOutBuffer is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	if (InBufferSize % AES_BLOCK_SIZE == 0 || InBufferSize < AES_BLOCK_SIZE)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->Buffer is aligned with block size.\n"));
		return STATUS_UNSUCCESSFUL;
	}


	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ULONG TailLength = InBufferSize % AES_BLOCK_SIZE;
	ULONG LengthReturned = 0;
	ULONG Cn_1Offset = 0, CnOffset = 0;

	CHAR Cn[AES_BLOCK_SIZE] = { 0 };
	CHAR Pn_1[AES_BLOCK_SIZE] = { 0 };
	CHAR Cpadding[AES_BLOCK_SIZE] = { 0 };

	PCHAR AlignedBuffer = NULL;

	AlignedBuffer = ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)InBufferSize - (SIZE_T)TailLength, READ_BUFFER_TAG);

	if (NULL == AlignedBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->ExAllocatePoolWithTag AlignedBuffer failed.\n"));
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}

	RtlZeroMemory(AlignedBuffer, InBufferSize - TailLength);

	RtlMoveMemory(AlignedBuffer, InBuffer, InBufferSize - TailLength);

	LengthReturned = InBufferSize - TailLength;
	Status = PocAesECBDecrypt(
		AlignedBuffer,
		InBufferSize - TailLength,
		InOutBuffer,
		&LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->PocAesECBDecrypt1 failed. Status = 0x%x\n", Status));
		goto EXIT;
	}

	Cn_1Offset = InBufferSize - TailLength - AES_BLOCK_SIZE;
	CnOffset = Cn_1Offset + AES_BLOCK_SIZE;

	//InOutBuffer + Cn_1Offset == Pn
	RtlMoveMemory(InOutBuffer + CnOffset, InOutBuffer + Cn_1Offset, TailLength);

	RtlMoveMemory(Cpadding, InOutBuffer + Cn_1Offset + TailLength, AES_BLOCK_SIZE - TailLength);

	RtlZeroMemory(InOutBuffer + Cn_1Offset, AES_BLOCK_SIZE);



	RtlMoveMemory(Cn, InBuffer + CnOffset, TailLength);
	RtlMoveMemory(Cn + TailLength, Cpadding, AES_BLOCK_SIZE - TailLength);

	LengthReturned = AES_BLOCK_SIZE;
	Status = PocAesECBDecrypt(
		Cn,
		AES_BLOCK_SIZE,
		Pn_1,
		&LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocAesECBDecrypt_CiphertextStealing->PocAesECBDecrypt2 failed. Status = 0x%x\n", Status));
		goto EXIT;
	}

	RtlMoveMemory(InOutBuffer + Cn_1Offset, Pn_1, AES_BLOCK_SIZE);

	Status = STATUS_SUCCESS;

EXIT:

	if (NULL != AlignedBuffer)
	{
		ExFreePoolWithTag(AlignedBuffer, READ_BUFFER_TAG);
		AlignedBuffer = NULL;
	}

	return Status;
}


NTSTATUS PocComputeHash(
	IN PUCHAR Data, 
	IN ULONG DataLength, 
	IN OUT PUCHAR* DataDigestPointer, 
	IN OUT ULONG* DataDigestLengthPointer)
{

	NTSTATUS Status = 0;

	BCRYPT_ALG_HANDLE HashAlgHandle = NULL;
	BCRYPT_HASH_HANDLE HashHandle = NULL;

	PUCHAR HashDigest = NULL;
	ULONG HashDigestLength = 0;

	ULONG ResultLength = 0;

	*DataDigestPointer = NULL;
	*DataDigestLengthPointer = 0;



	Status = BCryptOpenAlgorithmProvider(
		&HashAlgHandle,
		BCRYPT_SHA256_ALGORITHM,
		NULL,
		0);
	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->BCryptOpenAlgorithmProvider failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto cleanup;
	}




	Status = BCryptGetProperty(
		HashAlgHandle,
		BCRYPT_HASH_LENGTH,
		(PUCHAR)&HashDigestLength,
		sizeof(HashDigestLength),
		&ResultLength,
		0);
	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->BCryptGetProperty failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto cleanup;
	}


	HashDigest = (PUCHAR)ExAllocatePoolWithTag(PagedPool, HashDigestLength, READ_BUFFER_TAG);

	if (NULL == HashDigest)
	{
		Status = STATUS_NO_MEMORY;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ExAllocatePoolWithTag failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto cleanup;
	}

	RtlZeroMemory(HashDigest, HashDigestLength);



	Status = BCryptCreateHash(
		HashAlgHandle,
		&HashHandle,
		NULL,
		0,
		NULL,
		0,
		0);
	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->BCryptCreateHash failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto cleanup;
	}



	Status = BCryptHashData(
		HashHandle,
		(PUCHAR)Data,
		DataLength,
		0);
	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->BCryptHashData failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto cleanup;
	}



	Status = BCryptFinishHash(
		HashHandle,
		HashDigest,
		HashDigestLength,
		0);
	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->BCryptFinishHash failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto cleanup;
	}

	*DataDigestPointer = HashDigest;
	HashDigest = NULL;
	*DataDigestLengthPointer = HashDigestLength;

	Status = STATUS_SUCCESS;

cleanup:

	if (NULL != HashDigest)
	{
		ExFreePool(HashDigest);
		HashDigest = NULL;
	}

	if (NULL != HashHandle)
	{
		Status = BCryptDestroyHash(HashHandle);
		HashHandle = NULL;
	}

	if (NULL != HashAlgHandle)
	{
		BCryptCloseAlgorithmProvider(HashAlgHandle, 0);
		HashAlgHandle = NULL;
	}

	return Status;
}


/**
 * @Author: wangzhankun
 * @Date: 2022-06-22 20:22:32
 * @LastEditors: wangzhankun
 * @update:
 * @brief 对 read_buffer 进行 AES 解密，并将解密后的数据写入到 write_buffer 中。
 * 会根据 read_buffer 的长度和file_size的长度自动选择相应的解密函数（是padding解密还是密文挪用解密等）。
 * 如果需要密文挪用的话（即 file_size > AES_BLOCK_SIZE 且 file_size % AES_BLOCK_SIZE !=0 且 当前read_buffer中的数据就是文件中最末尾的数据），
 * 那就需要保证 bytesRead > AES_BLOCK_SIZE，否则就会出现由于无法进行密文挪用导致的错误。
 * @param [in] {PCHAR} read_buffer 待解密的数据
 * @param [in] {ULONG} bytesRead 传入的是解密后的明文的真实长度。这里的长度是指明文的长度。
 * 比如 如果明文长度只有18个字节，但是加密后会是 2 * AES_BLOCK_SIZE 的长度，那么此时 bytesRead 就是 18字节。
 * @param [in] {PCHAR} write_buffer 加密后的数据
 * @param [out] {ULONG*} 传入的是write_buffer缓冲区的大小；传出的是bytesWrite 解密后的明文长度。如果发生了错误或者file_size == 0，那么 bytesWrite传出的值为0
 * @param [in] {ULONG} file_size 文件的长度。要求是文件的实际内容（加密前）的大小，不能包含文件标识尾的长度。
 * 因为文件加密后的长度肯定是 AES_BLOCK_SIZE 的整数倍，因此不可以使用加密后的文件大小。而是实际的加密前的文件大小。
 * @return {NTSTATUS} STATUS_SUCCESS if successfule
 */
NTSTATUS PocManualDecrypt(PCHAR read_buffer,
								 IN ULONG bytesRead,
								 IN OUT PCHAR write_buffer,
								 OUT ULONG *bytesWrite,
								 IN const LONGLONG file_size)
{
	NTSTATUS Status = STATUS_SUCCESS;

	PCHAR cipher_text = read_buffer;
	PCHAR plain_text = write_buffer;
	if (file_size < AES_BLOCK_SIZE) //必须使用file_size进行判断
	{
		// 因此加密后的文件至少会有 AES_BLOCK_SIZE 的大小。所以这里做了修改。
		bytesRead = AES_BLOCK_SIZE;
		Status = PocAesECBDecrypt(cipher_text, bytesRead, plain_text, bytesWrite);
		if (STATUS_SUCCESS != Status)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d PocAesECBDecrypt failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
			goto EXIT;
		}
		*bytesWrite = (ULONG)file_size;
	}
	else if (bytesRead % AES_BLOCK_SIZE == 0) //必须使用bytesRead进行判断
	{
		Status = PocAesECBDecrypt(cipher_text, bytesRead, plain_text, bytesWrite);
		if (STATUS_SUCCESS != Status)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d PocAesECBDecrypt failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
			goto EXIT;
		}
	}
	else
	{
		// bytesRead 做了特殊处理，保证 bytesRead > AES_BLOCK_SIZE，可以做密文挪用的解密操作

		// 需要进行密文挪用，且此时的数据一定是最后一次读取到的数据
		// Status = PocAesECBDecrypt_CiphertextStealing(cipher_text, bytesRead, plain_text);
		bytesRead = ROUND_TO_SIZE(bytesRead, AES_BLOCK_SIZE);
		// *bytesWrite = ROUND_TO_SIZE(*bytesWrite, AES_BLOCK_SIZE);
		Status = PocAesECBDecrypt(cipher_text, bytesRead, plain_text, bytesWrite);

		if (STATUS_SUCCESS != Status)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d PocAesECBDecrypt_CiphertextStealing failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
			goto EXIT;
		}
		*bytesWrite = bytesRead;
	}

EXIT:
	if (STATUS_SUCCESS != Status)
	{
		*bytesWrite = 0;
	}
	return Status;
}

/**
 * @Author: wangzhankun
 * @Date: 2022-06-22 20:22:32
 * @LastEditors: wangzhankun
 * @update:
 * @brief 对 read_buffer 进行 AES 加密，并将加密后的数据写入到 write_buffer 中。
 * 会根据 read_buffer 的长度和 file_size 的长度自动选择是否对进行 padding 或者密文挪用 或者不做特殊处理。
 * 如果需要密文挪用的话（即 file_size > AES_BLOCK_SIZE 且 file_size % AES_BLOCK_SIZE !=0 且 当前read_buffer中的数据就是文件最后需要加密写入的数据），
 * 那就需要保证 bytesRead > AES_BLOCK_SIZE，否则会由于无法进行密文挪用而出现错误。
 * @param [in] {PCHAR} read_buffer 待加密的数据
 * @param [in] {ULONG} bytesRead 待加密的数据的长度。加密后的数据的长度也会由此传出。
 * 内部使用的是ECB，因此加密后的数据长度就是 bytesREAD 按照 AES_BLOCK_SIZE 取整后的长度。
 * @param [in] {PCHAR} write_buffer 加密后的数据
 * @param [in|out] {ULONG*} 传入的是write_buffer缓冲区的大小；传出的是bytesWrite 加密后的数据的长度，肯定是 AES_BLOCK_SIZE 的整数倍。如果发生了错误或者file_size == 0，那么 bytesWrite传出的值为0
 * @param [in] {ULONG} file_size 文件的长度。要求是文件的实际内容（加密前）的大小，不能包含文件标识尾的长度。
 * @return {NTSTATUS} STATUS_SUCCESS if successfule
 */
NTSTATUS PocManualEncrypt(PCHAR read_buffer,
								 IN ULONG bytesRead,
								 IN OUT PCHAR write_buffer,
								 OUT ULONG *bytesWrite,
								 IN const LONGLONG file_size)
{
	NTSTATUS Status = STATUS_SUCCESS;

	PCHAR plain_text = read_buffer;
	PCHAR cipher_text = write_buffer;
	if (file_size < AES_BLOCK_SIZE) //必须使用file_size进行判断
	{
		bytesRead = AES_BLOCK_SIZE; // padding

		Status = PocAesECBEncrypt(plain_text, bytesRead, cipher_text, bytesWrite); // bytesRead 会自动被加密函数设置为密文的大小
		if (STATUS_SUCCESS != Status)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d PocAesECBEncrypt failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
			goto EXIT;
		}
	}
	else if (bytesRead % AES_BLOCK_SIZE == 0) //必须使用bytesRead进行判断
	{
		Status = PocAesECBEncrypt(plain_text, bytesRead, cipher_text, bytesWrite);
		if (STATUS_SUCCESS != Status)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d PocAesECBEncrypt failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
			goto EXIT;
		}
	}
	else
	{
		// bytesRead 做了特殊处理，保证 bytesRead > AES_BLOCK_SIZE，可以做密文挪用

		// 需要进行密文挪用，且此时的数据一定是最后一次读取到的数据
		// Status = PocAesECBEncrypt_CiphertextStealing(plain_text, bytesRead, cipher_text);
		bytesRead = ROUND_TO_SIZE(bytesRead, AES_BLOCK_SIZE);
		// *bytesWrite = ROUND_TO_SIZE(*bytesWrite, AES_BLOCK_SIZE);
		Status = PocAesECBEncrypt(plain_text, bytesRead, cipher_text, bytesWrite);

		if (STATUS_SUCCESS != Status)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s@%s@%d PocAesECBEncrypt_CiphertextStealing failed: 0x%x\n", __FUNCTION__, __FILE__, __LINE__, Status));
			goto EXIT;
		}
		*bytesWrite = ROUND_TO_SIZE(bytesRead, AES_BLOCK_SIZE);
	}

EXIT:
	if (STATUS_SUCCESS != Status)
	{
		*bytesWrite = 0;
	}
	return Status;
}