
#include "utils.h"
#include "global.h"
#include "context.h"
#include <wdm.h>

UCHAR* PsGetProcessImageFileName(PEPROCESS EProcess);

NTSTATUS PocGetProcessName(
	IN PFLT_CALLBACK_DATA Data, 
	IN OUT PCHAR ProcessName)
{

	if (NULL == ProcessName)
	{
		DbgPrint("PocGetProcessName->ProcessName is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	PEPROCESS eProcess;

	eProcess = FltGetRequestorProcess(Data);

	if (!eProcess) {

		DbgPrint("PocGetProcessName->EProcess FltGetRequestorProcess failed.\n.");
		return STATUS_UNSUCCESSFUL;
	}

	if (strlen((PCHAR)PsGetProcessImageFileName(eProcess)) < POC_MAX_NAME_LENGTH)
	{
		RtlMoveMemory(ProcessName, PsGetProcessImageFileName(eProcess), strlen((PCHAR)PsGetProcessImageFileName(eProcess)));
	}
	
	return STATUS_SUCCESS;
}


NTSTATUS PocGetFileNameOrExtension(
	IN PFLT_CALLBACK_DATA Data, 
	IN OUT PWCHAR FileExtension, 
	IN OUT PWCHAR FileName)
{

	NTSTATUS Status;
	PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;


	Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &FileNameInfo);

	if (!NT_SUCCESS(Status)) 
	{
		if (STATUS_FLT_NAME_CACHE_MISS == Status)
		{
			DbgPrint("PocGetFileExtension->FltGetFileNameInformation failed. Status = STATUS_FLT_NAME_CACHE_MISS\n");
		}
		else
		{
			//DbgPrint("PocGetFileExtension->FltGetFileNameInformation failed. Status = 0x%x\n", Status);
		}
		return Status;
	}

	Status = FltParseFileNameInformation(FileNameInfo);

	if (STATUS_SUCCESS != Status)
	{
		goto EXIT;
	}

	if (NULL != FileExtension && 
		NULL != FileNameInfo->Extension.Buffer &&
		wcslen(FileNameInfo->Extension.Buffer) < POC_MAX_NAME_LENGTH)
	{
		RtlMoveMemory(FileExtension, FileNameInfo->Extension.Buffer, wcslen(FileNameInfo->Extension.Buffer) * sizeof(WCHAR));
	}
		
	if (NULL != FileName && 
		NULL != FileNameInfo->Name.Buffer &&
		wcslen(FileNameInfo->Name.Buffer) < POC_MAX_NAME_LENGTH)
	{
		RtlMoveMemory(FileName, FileNameInfo->Name.Buffer, wcslen(FileNameInfo->Name.Buffer) * sizeof(WCHAR));
	}
	
	//DbgPrint("PocGetFileExtension->FileName is %ws.\n", FileNameInfo->Name.Buffer);

EXIT:
	if (NULL != FileNameInfo)
	{
		FltReleaseFileNameInformation(FileNameInfo);
		FileNameInfo = NULL;
	}

	return Status;
}


ULONG PocQueryEndOfFileInfo(
	IN PFLT_INSTANCE Instance, 
	IN PFILE_OBJECT FileObject)
{

	FILE_STANDARD_INFORMATION StandardInfo = { 0 };
	ULONG LengthReturned = 0;
	NTSTATUS Status;

	Status = FltQueryInformationFile(Instance, FileObject, &StandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, &LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("PocQueryEndOfFileInfo->FltQueryInformationFile failed. Status = 0x%x.\n", Status);
		return 0;
	}

	return StandardInfo.EndOfFile.LowPart;
}


NTSTATUS PocSetEndOfFileInfo(
	IN PFLT_INSTANCE Instance, 
	IN PFILE_OBJECT FileObject, 
	IN ULONG FileSize)
{
	FILE_END_OF_FILE_INFORMATION EndOfFileInfo = { 0 };
	NTSTATUS Status;

	EndOfFileInfo.EndOfFile.LowPart = FileSize;

	Status = FltSetInformationFile(Instance, FileObject, &EndOfFileInfo, sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation);

	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("PocQueryEndOfFileInfo->FltSetInformationFile failed. Status = 0x%x.\n", Status);
	}

	return Status;
}


USHORT PocQueryVolumeSectorSize(IN PFLT_VOLUME Volume)
{
	//Therefore, a minifilter driver commonly calls this routine from a post-mount callback function 
	//or an InstanceSetupCallback (PFLT_INSTANCE_SETUP_CALLBACK) routine to determine whether to attach to a given volume.

	UCHAR VolPropBuffer[sizeof(FLT_VOLUME_PROPERTIES) + 512] = { 0 };
	PFLT_VOLUME_PROPERTIES VolProp = (PFLT_VOLUME_PROPERTIES)VolPropBuffer;
	ULONG LengthReturned = 0;
	NTSTATUS Status;

	Status = FltGetVolumeProperties(Volume, VolProp, sizeof(VolPropBuffer), &LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		DbgPrint("PocQueryVolumeSectorSize->FltGetVolumeProperties failed. Status = 0x%x.\n", Status);
		return 0;
	}

	return max(VolProp->SectorSize, MIN_SECTOR_SIZE);
}


NTSTATUS PocBypassIrrelevantProcess(IN PCHAR ProcessName)
{
	if (NULL == ProcessName)
	{
		DbgPrint("PocBypassIrrelevantProcess->ProcessName is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = 0;

	if (strncmp(ProcessName, "SearchUI.exe", strlen("SearchUI.exe")) == 0 ||
		strncmp(ProcessName, "TiWorker.exe", strlen("TiWorker.exe")) == 0)
	{
		Status = POC_IS_IRRELEVENT_PROCESS;
	}

	return Status;
}


NTSTATUS PocBypassIrrelevantPath(IN PWCHAR FileName)
{
	
	if (NULL == FileName)
	{
		DbgPrint("PocBypassWordBackupFile->FileName is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = STATUS_SUCCESS;

	PWCHAR lpFileName = NULL;

	lpFileName = FileName;

	while (lpFileName < FileName + wcslen(FileName))
	{

		if (wcsncmp(lpFileName, L"AppData", wcslen(L"AppData")) == 0 ||
			wcsncmp(lpFileName, L"~$", wcslen(L"~$")) == 0)
		{
			return POC_IS_IRRELEVENT_PATH;
		}

		lpFileName++;
	}

	return Status;
}


NTSTATUS PocParseFileNameExtension(
	IN PWCHAR FileName, 
	IN OUT PWCHAR FileExtension)
{
	if (NULL == FileName)
	{
		DbgPrint("PocParseFileNameExtension->FileName is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (NULL == FileExtension)
	{
		DbgPrint("PocParseFileNameExtension->FileExtension is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	PWCHAR lpExtension = NULL;

	lpExtension = FileName + wcslen(FileName);

	while (lpExtension > FileName)
	{
		if (*lpExtension == L'.' && wcslen(lpExtension) < POC_MAX_NAME_LENGTH)
		{
			lpExtension++;
			RtlMoveMemory(FileExtension, lpExtension, wcslen(lpExtension) * sizeof(WCHAR));
			return STATUS_SUCCESS;
		}

		lpExtension--;
	}

	return STATUS_UNSUCCESSFUL;
}


NTSTATUS PocBypassIrrelevantFileExtension(IN PWCHAR FileExtension)
{

	if (NULL == FileExtension)
	{
		DbgPrint("PocBypassIrrelevantFileExtension->FileExtension is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (wcsncmp(FileExtension, L"txt", wcslen(L"txt")) != 0 &&
		wcsncmp(FileExtension, L"docx", wcslen(L"docx")) != 0 &&
		wcsncmp(FileExtension, L"doc", wcslen(L"doc")) != 0 &&
		wcsncmp(FileExtension, L"pptx", wcslen(L"pptx")) != 0 &&
		wcsncmp(FileExtension, L"ppt", wcslen(L"ppt")) != 0 &&
		wcsncmp(FileExtension, L"xlsx", wcslen(L"xlsx")) != 0 &&
		wcsncmp(FileExtension, L"xls", wcslen(L"xls")) != 0 &&
		wcsncmp(FileExtension, L"PNG", wcslen(L"PNG")) != 0 &&
		wcsncmp(FileExtension, L"JPG", wcslen(L"JPG")) != 0)
	{
		return POC_IRRELEVENT_FILE_EXTENSION;
	}
	else
	{
		return POC_IS_TARGET_FILE_EXTENSION;
	}

}


NTSTATUS PocIsUnauthorizedProcess(IN PCHAR ProcessName)
{
	if (NULL == ProcessName)
	{
		DbgPrint("PocIsUnauthorizedProcess->ProcessName is NULL.\n");
		return STATUS_INVALID_PARAMETER;
	}

	if (strncmp(ProcessName, "notepad++.exe", strlen("notepad++.exe")) == 0/* ||
		strncmp(ProcessName, "notepad.exe", strlen("notepad.exe")) == 0*/)
	{
		return POC_IS_UNAUTHORIZED_PROCESS;
	}
	else
	{
		return POC_IS_AUTHORIZED_PROCESS;
	}

}


NTSTATUS PocQuerySymbolicLink(
	IN PUNICODE_STRING SymbolicLinkName, 
	OUT PUNICODE_STRING LinkTarget)
/*
* 文件路径磁盘转为DOS名
* \\??\\c:-->\\device\\\harddiskvolume1
* LinkTarget.Buffer注意要释放
*/
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	HANDLE LinkHandle = NULL;

	InitializeObjectAttributes(
		&ObjectAttributes,
		SymbolicLinkName,
		OBJ_CASE_INSENSITIVE,
		0,
		0);

	Status = ZwOpenSymbolicLinkObject(&LinkHandle, GENERIC_READ, &ObjectAttributes);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("PocQuerySymbolicLink->ZwOpenSymbolicLinkObject failed. Status = 0x%x.\n", Status);
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}

	LinkTarget->MaximumLength = 260 * sizeof(WCHAR);
	LinkTarget->Length = 0;
	LinkTarget->Buffer = ExAllocatePoolWithTag(NonPagedPool, LinkTarget->MaximumLength, DOS_NAME_BUFFER_TAG);

	if (NULL == LinkTarget->Buffer)
	{
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto EXIT;
	}

	RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);


	Status = ZwQuerySymbolicLinkObject(LinkHandle, LinkTarget, NULL);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("PocQuerySymbolicLink->ZwOpenSymbolicLinkObject failed. Status = 0x%x.\n", Status);
		ExFreePoolWithTag(LinkTarget->Buffer, DOS_NAME_BUFFER_TAG);
	}

	Status = STATUS_SUCCESS;

EXIT:

	if (NULL != LinkHandle)
	{
		ZwClose(LinkHandle);
		LinkHandle = NULL;
	}

	return Status;
}


NTSTATUS PocGetVolumeInstance(
	IN PFLT_FILTER pFilter, 
	IN PUNICODE_STRING pVolumeName, 
	OUT PFLT_INSTANCE* Instance)
/*
* 得到对应卷的实例
* pVolumeName->Buffer->L"\\Device\\HarddiskVolume2"
*/
{
	NTSTATUS		Status;
	PFLT_INSTANCE	pInstance = NULL;
	PFLT_VOLUME		pVolumeList[100];
	ULONG			uRet;
	UNICODE_STRING	uniName = { 0 };
	ULONG 			index = 0;
	WCHAR			wszNameBuffer[260] = { 0 };

	Status = FltEnumerateVolumes(pFilter,
		NULL,
		0,
		&uRet);
	if (Status != STATUS_BUFFER_TOO_SMALL)
	{
		return Status;
	}

	Status = FltEnumerateVolumes(pFilter,
		pVolumeList,
		uRet,
		&uRet);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	uniName.Buffer = wszNameBuffer;

	if (uniName.Buffer == NULL)
	{
		for (index = 0; index < uRet; index++)
			FltObjectDereference(pVolumeList[index]);

		return STATUS_UNSUCCESSFUL;
	}

	uniName.MaximumLength = sizeof(wszNameBuffer);

	for (index = 0; index < uRet; index++)
	{
		uniName.Length = 0;

		Status = FltGetVolumeName(pVolumeList[index],
			&uniName,
			NULL);

		if (!NT_SUCCESS(Status))
			continue;

		if (RtlCompareUnicodeString(&uniName,
			pVolumeName,
			TRUE) != 0)
			continue;

		Status = FltGetVolumeInstanceFromName(pFilter,
			pVolumeList[index],
			NULL,
			&pInstance);

		if (NT_SUCCESS(Status))
		{
			FltObjectDereference(pInstance);
			break;
		}
	}

	for (index = 0; index < uRet; index++)
	{
		FltObjectDereference(pVolumeList[index]);
	}

	*Instance = pInstance;

	return Status;
}
