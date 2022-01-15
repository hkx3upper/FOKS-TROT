#pragma once

#include <fltKernel.h>

NTSTATUS PocGetProcessName(
	IN PFLT_CALLBACK_DATA Data, 
	IN OUT PCHAR ProcessName);

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

NTSTATUS PocBypassIrrelevantProcess(IN PCHAR ProcessName);

NTSTATUS PocBypassIrrelevantPath(IN PWCHAR FileName);

NTSTATUS PocBypassIrrelevantFileExtension(IN PWCHAR FileExtension);

NTSTATUS PocIsUnauthorizedProcess(IN PCHAR ProcessName);

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
