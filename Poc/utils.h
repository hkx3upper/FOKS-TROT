#pragma once

#include "global.h"
#include "import.h"

NTSTATUS PocGetFileNameOrExtension(
	IN PFLT_CALLBACK_DATA Data, 
	IN OUT PWCHAR FileExtension, 
	IN OUT PWCHAR FileName);

ULONG PocQueryEndOfFileInfo(
	IN PFLT_INSTANCE Instance, 
	IN PFILE_OBJECT FileObject);

NTSTATUS PocSetEndOfFileInfo(
	IN PFLT_INSTANCE Instance, 
	IN PFILE_OBJECT FileObject, 
	IN ULONG FileSize);

USHORT PocQueryVolumeSectorSize(IN PFLT_VOLUME Volume);

NTSTATUS PocBypassBsodProcess(IN PFLT_CALLBACK_DATA Data);

NTSTATUS PocBypassIrrelevantPath(IN PWCHAR FileName);

NTSTATUS PocBypassIrrelevantFileExtension(IN PWCHAR FileExtension);

NTSTATUS PocIsUnauthorizedProcess(IN PWCHAR ProcessName);

NTSTATUS PocParseFileNameExtension(
	IN PWCHAR FileName, 
	IN OUT PWCHAR FileExtension);

NTSTATUS PocQuerySymbolicLink(
	IN PUNICODE_STRING SymbolicLinkName,
	OUT PUNICODE_STRING LinkTarget);

NTSTATUS PocGetVolumeInstance(
	IN PFLT_FILTER pFilter,
	IN PUNICODE_STRING pVolumeName,
	OUT PFLT_INSTANCE* Instance);

NTSTATUS PocSymbolLinkPathToDosPath(
	IN PWCHAR Path,
	IN OUT PWCHAR DosPath);

NTSTATUS PocSymbolLinkPathToDosPath(
	IN PWCHAR Path,
	IN OUT PWCHAR DosPath);

NTSTATUS PocInjectApc(
	IN PKTHREAD Thread,
	IN KPROCESSOR_MODE ApcMode,
	IN PKNORMAL_ROUTINE NormalRoutine,
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);