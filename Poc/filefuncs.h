#pragma once

#include "global.h"
#include "context.h"
#include "utils.h"

typedef struct _POC_ENCRYPTION_TAILER
{
	CHAR Flag[32];
	WCHAR FileName[POC_MAX_NAME_LENGTH];
	LONGLONG FileSize;
	BOOLEAN IsCipherText;
	CHAR EncryptionAlgorithmType[32];
	CHAR KeyAndCiphertextHash[32];
	CHAR CipherText[16];//用于记录文件大小不足一个 AES_BLOCK_SIZE 时多余的密文
}POC_ENCRYPTION_TAILER, * PPOC_ENCRYPTION_TAILER;

extern POC_ENCRYPTION_TAILER EncryptionTailer;

NTSTATUS PocReadFileNoCache(
	IN PFLT_INSTANCE Instance,
	IN PFLT_VOLUME Volume,
	IN PWCHAR FileName,
	IN LARGE_INTEGER ByteOffset,
	IN ULONG ReadLength,
	OUT PCHAR* OutReadBuffer,
	IN OUT PULONG BytesRead);

NTSTATUS PocWriteFileIntoCache(
	IN PFLT_INSTANCE Instance,
	IN PFILE_OBJECT FileObject,
	IN LARGE_INTEGER ByteOffset,
	IN PCHAR WriteBuffer,
	IN ULONG WriteLength);

NTSTATUS PocCreateFileForEncTailer(
	IN PCFLT_RELATED_OBJECTS FltObjects,
	IN PPOC_STREAM_CONTEXT StreamContext,
	IN PWCHAR ProcessName);

NTSTATUS PocAppendEncTailerToFile(
	IN PFLT_VOLUME Volume,
	IN PFLT_INSTANCE Instance,
	IN PPOC_STREAM_CONTEXT StreamContext);

NTSTATUS PocNtfsFlushAndPurgeCache(
	IN PFLT_INSTANCE Instance,
	IN PFILE_OBJECT FileObject);

NTSTATUS PocFlushOriginalCache(
	IN PFLT_INSTANCE Instance,
	IN PWCHAR FileName);

NTSTATUS PocReentryToEncrypt(
	IN PFLT_INSTANCE Instance,
	IN PWCHAR FileName);

NTSTATUS PocReentryToDecrypt(
	IN PFLT_INSTANCE Instance,
	IN PWCHAR FileName);

KSTART_ROUTINE PocAppendEncTailerThread;

NTSTATUS PocReadFileFromCache(
	IN PFLT_INSTANCE Instance,
	IN PFILE_OBJECT FileObject,
	IN LARGE_INTEGER ByteOffset,
	IN PCHAR ReadBuffer,
	IN ULONG ReadLength);

NTSTATUS PocInitFlushFileObject(
	IN PWCHAR FileName,
	IN OUT PFILE_OBJECT* FileObject);

NTSTATUS PocFindOrCreateStreamContextOutsite(
	IN PFLT_INSTANCE Instance,
	IN PWCHAR FileName,
	IN BOOLEAN CreateIfNotFound);


/**
 * @Author: wangzhankun
 * @Date: 2022-06-21 15:29:06
 * @LastEditors: wangzhankun
 * @update:
 * @brief 判断 encryption_tailer 究竟是不是 encryption_tailer
 * @param {PPOC_ENCRYPTION_TAILER} encryption_tailer
 * @return true if it is encryption_tailer, false otherwise
 */
BOOLEAN PocIsAppendEncryptionTailer(PPOC_ENCRYPTION_TAILER encryption_tailer);

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
                               _In_ PFILE_OBJECT FileObject);
VOID PocPurgeCache(
	IN PWCHAR FileName,
	IN PFLT_INSTANCE Instance,
	IN PSECTION_OBJECT_POINTERS SectionObjectPointers);
