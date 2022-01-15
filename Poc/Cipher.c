

#include "cipher.h"
#include "global.h"

AES_INIT_VARIABLES AesInitVar;


NTSTATUS PocInitAesECBKey()
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
		DbgPrint("PocInitAesECBKey->BCryptOpenAlgorithmProvider failed. Status = 0x%x.\n", Status);
		goto ERROR;
	}
	
	Status = BCryptGetProperty(AesInitVar.hAesAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(ULONG), &cbData, 0);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("PocInitAesECBKey->BCryptGetProperty failed. Status = 0x%x.\n", Status);
		goto ERROR;
	}

	AesInitVar.pbKeyObject = ExAllocatePoolWithTag(NonPagedPool, cbKeyObject, KEY_OBJECT_BUFFER);

	if (NULL == AesInitVar.pbKeyObject)
	{
		DbgPrint("PocInitAesECBKey->ExAllocatePoolWithTag pbKeyObject failed.\n");
		goto ERROR;
	}

	Status = BCryptSetProperty(AesInitVar.hAesAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("PocInitAesECBKey->BCryptSetProperty failed. Status = 0x%x.\n", Status);
		goto ERROR;
	}

	Status = BCryptGenerateSymmetricKey(AesInitVar.hAesAlg, &AesInitVar.hKey, AesInitVar.pbKeyObject, cbKeyObject, rgbAES128Key, sizeof(rgbAES128Key), 0);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("PocInitAesECBKey->BCryptGenerateSymmetricKey failed. Status = 0x%x.\n", Status);
		goto ERROR;
	}

	Status = STATUS_SUCCESS;
	AesInitVar.Flag = TRUE;
	goto EXIT;

ERROR:
	if (NULL != AesInitVar.hAesAlg)
	{
		BCryptCloseAlgorithmProvider(AesInitVar.hAesAlg, 0);
		AesInitVar.hAesAlg = 0;
	}

	if (NULL != AesInitVar.pbKeyObject)
	{
		ExFreePoolWithTag(AesInitVar.pbKeyObject, KEY_OBJECT_BUFFER);
		AesInitVar.pbKeyObject = NULL;
	}

	if (NULL != AesInitVar.hKey)
	{
		BCryptDestroyKey(AesInitVar.hKey);
		AesInitVar.hKey = NULL;
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

	if (NULL != AesInitVar.hAesAlg)
	{
		BCryptCloseAlgorithmProvider(AesInitVar.hAesAlg, 0);
		AesInitVar.hAesAlg = NULL;
	}

	if (NULL != AesInitVar.pbKeyObject)
	{
		ExFreePoolWithTag(AesInitVar.pbKeyObject, KEY_OBJECT_BUFFER);
		AesInitVar.pbKeyObject = NULL;
	}

	if (NULL != AesInitVar.hKey)
	{
		BCryptDestroyKey(AesInitVar.hKey);
		AesInitVar.hKey = NULL;
	}

	AesInitVar.Flag = FALSE;
}


NTSTATUS PocAesECBEncrypt(
	IN PCHAR InBuffer, 
	IN ULONG InBufferSize, 
	IN OUT PCHAR InOutBuffer, 
	IN OUT PULONG LengthReturned)
{
	//LengthReturned�Ǹ��õģ��ڼ���ʱ������ΪInOutBuffer���ڴ��С���룬Ҳ��Ϊ���ܺ����Ĵ�С���

	if (!AesInitVar.Flag)
	{
		DbgPrint("PocAesECBEncrypt->AesInitVar.Flag = FALSE.\n");
		return POC_STATUS_AES_INIT_FAILED;
	}

	if (NULL == InBuffer)
	{
		DbgPrint("PocAesECBEncrypt->InBuffer is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == LengthReturned)
	{
		DbgPrint("PocAesECBEncrypt->LengthReturned is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}


	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	

	Status = BCryptEncrypt(AesInitVar.hKey, (PUCHAR)InBuffer, InBufferSize,
		NULL, NULL, 0, (PUCHAR)InOutBuffer, *LengthReturned, LengthReturned, 0);

	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("PocAesECBEncrypt->BCryptEncrypt encrypt plaintext failed. Status = 0x%x\n", Status);
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
		DbgPrint("PocAesECBDecrypt->AesInitVar.Flag = FALSE.\n");
		return POC_STATUS_AES_INIT_FAILED;
	}

	if (NULL == InBuffer)
	{
		DbgPrint("PocAesECBDecrypt->InBuffer is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == LengthReturned)
	{
		DbgPrint("PocAesECBDecrypt->LengthReturned is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}


	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	Status = BCryptDecrypt(AesInitVar.hKey, (PUCHAR)InBuffer, (ULONG)InBufferSize,
		NULL, NULL, 0, (PUCHAR)InOutBuffer, *LengthReturned, LengthReturned, 0);

	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("PocAesECBDecrypt->BCryptDecrypt decrypt ciphertext failed. Status = 0x%x\n", Status);
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
		DbgPrint("PocAesECBEncrypt_CiphertextStealing->AesInitVar.Flag = FALSE.\n");
		return POC_STATUS_AES_INIT_FAILED;
	}

	if (NULL == InBuffer)
	{
		DbgPrint("PocAesECBEncrypt_CiphertextStealing->InBuffer is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == InOutBuffer)
	{
		DbgPrint("PocAesECBEncrypt_CiphertextStealing->InOutBuffer is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (InBufferSize % AES_BLOCK_SIZE == 0 || InBufferSize < AES_BLOCK_SIZE)
	{
		DbgPrint("PocAesECBEncrypt_CiphertextStealing->Buffer is aligned with block size.\n");
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
		DbgPrint("PocAesECBEncrypt_CiphertextStealing->ExAllocatePoolWithTag AlignedBuffer failed.\\n");
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
		DbgPrint("PocAesECBEncrypt_CiphertextStealing->PocAesECBEncrypt1 failed. Status = 0x%x\n", Status);
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
		DbgPrint("PocAesECBEncrypt_CiphertextStealing->PocAesECBEncrypt2 failed. Status = 0x%x\n", Status);
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
		DbgPrint("PocAesECBDecrypt_CiphertextStealing->AesInitVar.Flag = FALSE.\n");
		return POC_STATUS_AES_INIT_FAILED;
	}

	if (NULL == InBuffer)
	{
		DbgPrint("PocAesECBDecrypt_CiphertextStealing->InBuffer is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == InOutBuffer)
	{
		DbgPrint("PocAesECBDecrypt_CiphertextStealing->InOutBuffer is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (InBufferSize % AES_BLOCK_SIZE == 0 || InBufferSize < AES_BLOCK_SIZE)
	{
		DbgPrint("PocAesECBDecrypt_CiphertextStealing->Buffer is aligned with block size.\n");
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
		DbgPrint("PocAesECBDecrypt_CiphertextStealing->ExAllocatePoolWithTag AlignedBuffer failed.\\n");
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
		DbgPrint("PocAesECBDecrypt_CiphertextStealing->PocAesECBDecrypt1 failed. Status = 0x%x\n", Status);
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
		DbgPrint("PocAesECBDecrypt_CiphertextStealing->PocAesECBDecrypt2 failed. Status = 0x%x\n", Status);
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


NTSTATUS PocStreamModeEncrypt(
	IN PCHAR InBuffer,
	IN ULONG InBufferSize,
	IN OUT PCHAR InOutBuffer)
{

	if (NULL == InBuffer)
	{
		DbgPrint("PocStreamModeEncrypt->InBuffer is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == InOutBuffer)
	{
		DbgPrint("PocStreamModeEncrypt->InOutBuffer is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	for (ULONG i = 0; i < InBufferSize; i++) 
	{
		*(InOutBuffer + i) = *(InBuffer + i) ^ 0x77;
	}

	return STATUS_SUCCESS;
}


NTSTATUS PocStreamModeDecrypt(
	IN PCHAR InBuffer,
	IN ULONG InBufferSize,
	IN OUT PCHAR InOutBuffer)
{

	if (NULL == InBuffer)
	{
		DbgPrint("PocStreamModeDecrypt->InBuffer is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == InOutBuffer)
	{
		DbgPrint("PocStreamModeDecrypt->InOutBuffer is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	for (ULONG i = 0; i < InBufferSize; i++)
	{
		*(InOutBuffer + i) = *(InBuffer + i) ^ 0x77;
	}

	return STATUS_SUCCESS;
}