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

NTSTATUS PocComputeHash(
	IN PUCHAR Data,
	IN ULONG DataLength,
	IN OUT PUCHAR* DataDigestPointer,
	IN OUT ULONG* DataDigestLengthPointer);

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
								 IN const LONGLONG file_size);


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
								 IN const LONGLONG file_size);
