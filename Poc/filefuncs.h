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
