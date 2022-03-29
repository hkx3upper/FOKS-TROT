#pragma once

#include <fltKernel.h>
#include <bcrypt.h>

#define AES_BLOCK_SIZE 16
#define KEY_OBJECT_BUFFER 'koBF'

typedef struct AES_INIT_VARIABLES
{
	BCRYPT_ALG_HANDLE hAesAlg;
	BCRYPT_KEY_HANDLE hKey;
	PUCHAR pbKeyObject;
	BOOLEAN Flag;

}AES_INIT_VARIABLES, * PAES_INIT_VARIABLES;

extern AES_INIT_VARIABLES AesInitVar;

NTSTATUS PocInitAesECBKey();

VOID PocAesCleanup();

NTSTATUS PocAesECBEncrypt(
	IN PCHAR InBuffer, 
	IN ULONG InBufferSize, 
	IN OUT PCHAR InOutBuffer, 
	IN OUT PULONG LengthReturned);

NTSTATUS PocAesECBDecrypt(
	IN PCHAR InBuffer, 
	IN ULONG InBufferSize, 
	IN OUT PCHAR InOutBuffer, 
	IN OUT PULONG LengthReturned);

NTSTATUS PocAesECBEncrypt_CiphertextStealing(
	IN PCHAR InBuffer,
	IN ULONG InBufferSize,
	IN OUT PCHAR InOutBuffer);

NTSTATUS PocAesECBDecrypt_CiphertextStealing(
	IN PCHAR InBuffer,
	IN ULONG InBufferSize,
	IN OUT PCHAR InOutBuffer);

NTSTATUS PocStreamModeEncrypt(
	IN PCHAR InBuffer,
	IN ULONG InBufferSize,
	IN OUT PCHAR InOutBuffer);

NTSTATUS PocStreamModeDecrypt(
	IN PCHAR InBuffer,
	IN ULONG InBufferSize,
	IN OUT PCHAR InOutBuffer);

NTSTATUS PocComputeHash(
	IN PUCHAR Data,
	IN ULONG DataLength,
	IN OUT PUCHAR* DataDigestPointer,
	IN OUT ULONG* DataDigestLengthPointer);
