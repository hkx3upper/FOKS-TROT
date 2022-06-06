
#include "processecure.h"
#include "process.h"
#include "utils.h"
#include "ldrreloc.h"
#include "cipher.h"

HANDLE gObjectHandle = NULL;

KSTART_ROUTINE PocProcessIntegrityCheckThread;


NTSTATUS PocProcessIntegrityCheck(
	IN PEPROCESS EProcess)
/*
* 对进程的代码段进行校验，后续也可将进程内的所有dll的代码段进行校验，
* 防止hook；或者对进程本身做签名验证
*/
{

	if (NULL == EProcess)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->EProcess is NULL.\n", __FUNCTION__));
		return STATUS_INVALID_PARAMETER;
	}


	NTSTATUS Status = 0;

	PUNICODE_STRING uProcessName = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

	HANDLE FileHandle = NULL;
	IO_STATUS_BLOCK IoStatus = { 0 };

	FILE_STANDARD_INFORMATION FileStandInfo;

	PCHAR ProcessBuffer = NULL;
	LARGE_INTEGER ByteOffset;

	PCHAR ProcessImage = NULL;
	PIMAGE_NT_HEADERS pHeaders = NULL;
	ULONG SizeOfProcessImage = 0;

	SIZE_T TextSectionVA = { 0 };
	SIZE_T TextSectionSize = { 0 };

	KAPC_STATE Apc;
	PCHAR OriginProcessImageBase = NULL;
	PPEB Peb = NULL;
	PPEB32 Peb32 = NULL;
	HANDLE hProcess = NULL;
	ULONG OldProt = 0;

	ULONG LengthReturned = 0;
	PUCHAR Hash1 = NULL, Hash2 = NULL;


	Status = SeLocateProcessImageName(EProcess, &uProcessName);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->SeLocateProcessImageName EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, EProcess, Status));

		goto EXIT;
	}

	/*
	* 从这里开始，先读出磁盘中的进程文件，存在ProcessBuffer中
	*/


	InitializeObjectAttributes(
		&ObjectAttributes, 
		uProcessName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 
		NULL, 
		NULL);

	Status = ZwOpenFile(
		&FileHandle,
		FILE_GENERIC_READ,
		&ObjectAttributes,
		&IoStatus,
		FILE_SHARE_READ | FILE_SHARE_DELETE,
		FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_NONALERT);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ZwOpenFile failed. Status = 0x%x.", __FUNCTION__, Status));
		goto EXIT;
	}


	Status = ZwQueryInformationFile(
		FileHandle,
		&IoStatus,
		&FileStandInfo,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ZwQueryInformationFile failed. Status = 0x%x.", __FUNCTION__, Status));
		goto EXIT;
	}

	ProcessBuffer = ExAllocatePoolWithTag(
		PagedPool,
		FileStandInfo.EndOfFile.LowPart,
		READ_BUFFER_TAG);

	if (NULL == ProcessBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
			("%s->ExAllocatePoolWithTag ProcessBuffer failed.\n", __FUNCTION__));
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}

	RtlZeroMemory(ProcessBuffer, FileStandInfo.EndOfFile.LowPart);

	ByteOffset.QuadPart = 0;
	Status = ZwReadFile(
		FileHandle,
		NULL, 
		NULL, 
		NULL,
		&IoStatus,
		ProcessBuffer,
		(ULONG)FileStandInfo.EndOfFile.QuadPart,
		&ByteOffset,
		NULL);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ZwReadFile failed. Status = 0x%x.", __FUNCTION__, Status));
		goto EXIT;
	}


	/*
	* 处于安全性的考虑，这里必须对磁盘中的进程文件做一个整体的校验，验证验证签名啥的
	* 暂时没做
	*/


	/*
	* 把磁盘中的进程文件ProcessBuffer，按节对齐映射到ProcessImage中
	*/

	pHeaders= RtlImageNtHeader(ProcessBuffer);

	SizeOfProcessImage = HEADER_VAL_T(pHeaders, SizeOfImage);

	ProcessImage = ExAllocatePoolWithTag(
		PagedPool,
		HEADER_VAL_T(pHeaders, SizeOfImage),
		READ_BUFFER_TAG);

	if (NULL == ProcessImage)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ExAllocatePoolWithTag ProcessImage failed.\n", __FUNCTION__));
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}

	RtlZeroMemory(ProcessImage, HEADER_VAL_T(pHeaders, SizeOfImage));


	RtlCopyMemory(ProcessImage, ProcessBuffer, HEADER_VAL_T(pHeaders, SizeOfHeaders));




	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHeaders + 1);
	if (IMAGE32(pHeaders))
		pFirstSection = (PIMAGE_SECTION_HEADER)((PIMAGE_NT_HEADERS32)pHeaders + 1);

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection;
		pSection < pFirstSection + pHeaders->FileHeader.NumberOfSections;
		pSection++)
	{

		if (!(pSection->Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) ||
			pSection->SizeOfRawData == 0)
		{
			continue;
		}

		/*
		* 记录.text节的偏移和大小
		*/
		if (!_strnicmp((PCHAR)pSection->Name, ".text", strlen(".text")))
		{
			TextSectionVA = pSection->VirtualAddress;
			TextSectionSize = pSection->Misc.VirtualSize;
		}

		RtlCopyMemory(
			ProcessImage + pSection->VirtualAddress,
			ProcessBuffer + pSection->PointerToRawData,
			pSection->SizeOfRawData
		);
	}


	if (0 == TextSectionVA || 0 == TextSectionSize)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->TextSectionVA || TextSectionSize is null.\n", __FUNCTION__));
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}



	/*
	* 附加到目标进程（待校验的进程）中，从PEB中获取ImageBaseAddress
	* 顺便通过PEB判断一下是否被调试
	*/
	KeStackAttachProcess(EProcess, &Apc);

	if (IMAGE32(pHeaders))
	{
		Peb32 = (PPEB32)PsGetProcessWow64Process(EProcess);

		if (NULL == Peb32)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->Peb32 is null.\n", __FUNCTION__));

			KeUnstackDetachProcess(&Apc);

			Status = STATUS_UNSUCCESSFUL;
			goto EXIT;
		}

		OriginProcessImageBase = (PCHAR)Peb32->ImageBaseAddress;

		if (TRUE == Peb32->BeingDebugged)
		{

			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->BeingDebugged process = %ws.\n", __FUNCTION__, uProcessName->Buffer));

			/*
			* 这里选择做点什么，比如直接蓝屏，结束进程等
			*/

			KeUnstackDetachProcess(&Apc);

			Status = STATUS_UNSUCCESSFUL;
			goto EXIT;
		}
	}
	else
	{
		Peb = PsGetProcessPeb(EProcess);

		if (NULL == Peb)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->Peb is null.\n", __FUNCTION__));

			KeUnstackDetachProcess(&Apc);

			Status = STATUS_UNSUCCESSFUL;
			goto EXIT;
		}

		OriginProcessImageBase = Peb->ImageBaseAddress;

		if (TRUE == Peb->BeingDebugged)
		{
		
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->BeingDebugged process = %ws.\n", __FUNCTION__, uProcessName->Buffer));

			/*
			* 这里选择做点什么，比如直接蓝屏，结束进程等
			*/

			KeUnstackDetachProcess(&Apc);

			Status = STATUS_UNSUCCESSFUL;
			goto EXIT;
		}
	}

	

	if (NULL == OriginProcessImageBase)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->OriginProcessImageBase is null.\n", __FUNCTION__));

		KeUnstackDetachProcess(&Apc);

		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}



	/*
	* 修改目标进程.text的保护，改成可读可执行
	*/
	Status = ObOpenObjectByPointer(
		EProcess,
		OBJ_KERNEL_HANDLE,
		NULL,
		0,
		*PsProcessType,
		KernelMode,
		&hProcess);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ObOpenObjectByPointer failed. Status = 0x%x.\n", __FUNCTION__, Status));

		KeUnstackDetachProcess(&Apc);

		goto EXIT;
	}


	TextSectionSize = ROUND_TO_PAGES(TextSectionSize);
	PVOID TextAddr = OriginProcessImageBase + TextSectionVA;

	Status = ZwProtectVirtualMemory(
		hProcess, 
		&TextAddr,
		&TextSectionSize,
		PAGE_EXECUTE_READ,
		&OldProt);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ZwProtectVirtualMemory1 failed. Status = 0x%x.\n", __FUNCTION__, Status));

		KeUnstackDetachProcess(&Apc);

		goto EXIT;
	}

	/*
	* 计算目标进程.text的哈希
	*/
	Status = PocComputeHash(
		(PUCHAR)OriginProcessImageBase + TextSectionVA, 
		(ULONG)TextSectionSize, 
		&Hash1, 
		&LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocComputeHash1 failed. Status = 0x%x.\n", __FUNCTION__, Status));

		KeUnstackDetachProcess(&Apc);

		goto EXIT;
	}


	Status = ZwProtectVirtualMemory(
		hProcess,
		&TextAddr,
		&TextSectionSize,
		OldProt,
		&OldProt);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->ZwProtectVirtualMemory2 failed. Status = 0x%x.\n", __FUNCTION__, Status));

		KeUnstackDetachProcess(&Apc);

		goto EXIT;
	}

	
	KeUnstackDetachProcess(&Apc);
	

	/*
	* 对磁盘映射的进程文件ProcessImage进行重定位
	*/
	Status = LdrRelocateImage(
		ProcessImage,
		OriginProcessImageBase,
		STATUS_SUCCESS,
		STATUS_CONFLICTING_ADDRESSES,
		STATUS_INVALID_IMAGE_FORMAT);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->LdrRelocateImage failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}


	Status = PocComputeHash(
		(PUCHAR)ProcessImage + TextSectionVA,
		(ULONG)TextSectionSize,
		&Hash2,
		&LengthReturned);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocComputeHash2 failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}

	if (0 != strncmp((PCHAR)Hash1, (PCHAR)Hash2, LengthReturned))
	{
		Status = POC_PROCESS_INTEGRITY_DAMAGE;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->Integrity check failed. Process %ws .text inconsistent.\n", __FUNCTION__, uProcessName->Buffer));

		/*
		* 这里选择做点什么，比如直接蓝屏，结束进程等
		*/

		goto EXIT;
	}
	else
	{
		Status = STATUS_SUCCESS;
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->Integrity check success. Process %ws .text consistent.\n", __FUNCTION__, uProcessName->Buffer));
		goto EXIT;
	}



EXIT:

	if (NULL != uProcessName)
	{
		ExFreePool(uProcessName);
		uProcessName = NULL;
	}

	if (NULL != FileHandle) 
	{
		ZwClose(FileHandle);
		FileHandle = NULL;
	}

	if (NULL != ProcessBuffer)
	{
		ExFreePoolWithTag(ProcessBuffer, READ_BUFFER_TAG);
		ProcessBuffer = NULL;
	}

	if (NULL != ProcessImage)
	{
		ExFreePoolWithTag(ProcessImage, READ_BUFFER_TAG);
		ProcessImage = NULL;
	}

	if (NULL != hProcess)
	{
		ZwClose(hProcess);
		hProcess = NULL;
	}

	if (NULL != Hash1)
	{
		ExFreePool(Hash1);
		Hash1 = NULL;
	}

	if (NULL != Hash2)
	{
		ExFreePool(Hash2);
		Hash2 = NULL;
	}

	return Status;
}


VOID PocProcessIntegrityCheckThread(
	IN PVOID StartContext)
{

	UNREFERENCED_PARAMETER(StartContext);

	NTSTATUS Status = STATUS_SUCCESS;

	LARGE_INTEGER Interval = { 0 };
	Interval.QuadPart = -100 * 1000 * 1000;

	/*
	* 线程会在PocProcessCleanup()释放掉gObjectHandle后退出循环
	*/
	
	while (NULL != gObjectHandle)
	{

		Status = KeDelayExecutionThread(KernelMode, FALSE, &Interval);

		if (NULL == gObjectHandle)
		{
			break;
		}

		PocFindProcessInfoNodeByPidEx(NULL,
			NULL,
			FALSE,
			TRUE);
	}


	PsTerminateSystemThread(Status);
}


OB_PREOP_CALLBACK_STATUS PocPreObjectOperation(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);

	/*
	* 整体放入PocDoCompletionProcessingWhenSafe函数中，未做
	*/

	PAGED_CODE();

	OB_PREOP_CALLBACK_STATUS Status = { 0 };

	HANDLE ProcessId = NULL;
	PPOC_CREATED_PROCESS_INFO OutProcessInfo = NULL;

	HANDLE RequestProcessId = NULL;
	PEPROCESS RequestEProcess = NULL;
	PUNICODE_STRING uProcessName = NULL;

	WCHAR CsrssDosPath[POC_MAX_NAME_LENGTH] = { 0 };
	WCHAR SvchostDosPath[POC_MAX_NAME_LENGTH] = { 0 };
	WCHAR ExplorerDosPath[POC_MAX_NAME_LENGTH] = { 0 };
	WCHAR WmiPrvSEDosPath[POC_MAX_NAME_LENGTH] = { 0 };
	WCHAR TaskmgrDosPath[POC_MAX_NAME_LENGTH] = { 0 };
	WCHAR LsassDosPath[POC_MAX_NAME_LENGTH] = { 0 };


	if (*PsProcessType == OperationInformation->ObjectType)
	{
		ProcessId = PsGetProcessId(OperationInformation->Object);

		if (NULL == ProcessId)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->PsGetProcessId EProcess = %p failed. Status = 0x%x.\n",
					__FUNCTION__,
					OperationInformation->Object,
					Status));

			goto EXIT;
		}
	}
	else if (*PsThreadType == OperationInformation->ObjectType)
	{
		ProcessId = PsGetThreadProcessId(OperationInformation->Object);

		if (NULL == ProcessId)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->PsGetThreadProcessId EThread = %p failed. Status = 0x%x.\n",
					__FUNCTION__,
					OperationInformation->Object,
					Status));

			goto EXIT;
		}
	}
	

	Status = PocFindProcessInfoNodeByPidEx(ProcessId, &OutProcessInfo, FALSE, FALSE);

	if (STATUS_SUCCESS != Status)
	{
		goto EXIT;
	}

	/*
	* 等到进程的第一个线程创建再过滤Object，否则进程创建会失败
	*/
	if (FALSE == OutProcessInfo->ThreadStartUp)
	{
		goto EXIT;
	}

	/*
	* 如果是进程自己的线程读写Object，放过
	*/
	RequestProcessId = PsGetThreadProcessId((PETHREAD)PsGetCurrentThread());

	if (RequestProcessId == ProcessId)
	{
		goto EXIT;
	}

	if (TRUE == OperationInformation->KernelHandle)
	{
		goto EXIT;
	}


	/*
	* 如果请求的进程已经在进程链表中，我们默认它是安全的，放过
	*/
	Status = PocFindProcessInfoNodeByPidEx(RequestProcessId, NULL, FALSE, FALSE);

	if (STATUS_SUCCESS == Status)
	{
		goto EXIT;
	}

	/*
	* 对一些系统进程放过，防止进程无法启动，
	* 这里应该对csrss.exe lsass.exe的句柄进行降权或剥离，或者直接注入dll
	*/
	Status = PsLookupProcessByProcessId(RequestProcessId, &RequestEProcess);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PsLookupProcessByProcessId RequestProcessId = %I64d failed. Status = 0x%x.\n",
			__FUNCTION__,
			(LONGLONG)RequestProcessId,
			Status));

		goto EXIT;
	}


	Status = SeLocateProcessImageName(RequestEProcess, &uProcessName);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->SeLocateProcessImageName EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}





	Status = PocSymbolLinkPathToDosPath(POC_CSRSS_PATH, CsrssDosPath);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
			("%s->PocSymbolLinkPathToDosPath EProcess = %p failed. Status = 0x%x.\n", 
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}

	Status = PocSymbolLinkPathToDosPath(POC_SVCHOST_PATH, SvchostDosPath);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocSymbolLinkPathToDosPath EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}

	Status = PocSymbolLinkPathToDosPath(POC_EXPLORER_PATH, ExplorerDosPath);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocSymbolLinkPathToDosPath EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}

	Status = PocSymbolLinkPathToDosPath(POC_WMIPRVSE_PATH, WmiPrvSEDosPath);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocSymbolLinkPathToDosPath EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}

	Status = PocSymbolLinkPathToDosPath(POC_TASKMGR_PATH, TaskmgrDosPath);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocSymbolLinkPathToDosPath EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}

	Status = PocSymbolLinkPathToDosPath(POC_LSASS_PATH, LsassDosPath);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocSymbolLinkPathToDosPath EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, RequestEProcess, Status));

		goto EXIT;
	}


	if (!_wcsnicmp(CsrssDosPath, uProcessName->Buffer, uProcessName->Length / sizeof(WCHAR)) ||
		!_wcsnicmp(SvchostDosPath, uProcessName->Buffer, uProcessName->Length / sizeof(WCHAR)) ||
		!_wcsnicmp(ExplorerDosPath, uProcessName->Buffer, uProcessName->Length / sizeof(WCHAR)) ||
		!_wcsnicmp(WmiPrvSEDosPath, uProcessName->Buffer, uProcessName->Length / sizeof(WCHAR)) ||
		!_wcsnicmp(TaskmgrDosPath, uProcessName->Buffer, uProcessName->Length / sizeof(WCHAR)) ||
		!_wcsnicmp(LsassDosPath, uProcessName->Buffer, uProcessName->Length / sizeof(WCHAR)))
	{
		goto EXIT;
	}



	if (OB_OPERATION_HANDLE_CREATE == OperationInformation->Operation)
	{

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_OPERATION))
				ClearFlag(OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
					PROCESS_VM_OPERATION);

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_READ))
			ClearFlag(OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
				PROCESS_VM_READ);

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_WRITE))
			ClearFlag(OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
				PROCESS_VM_WRITE);

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE))
		{
			/*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->Handle create ProcessId = %I64d ProcessName = %ws RequestProcessId = %I64d Kernel = %d access denied.\n",
					__FUNCTION__,
					(LONGLONG)ProcessId,
					NULL != OutProcessInfo->OwnedProcessRule ?
					OutProcessInfo->OwnedProcessRule->ProcessName : NULL,
					(LONGLONG)RequestProcessId,
					OperationInformation->KernelHandle));*/
		}

	}
	else if (OB_OPERATION_HANDLE_DUPLICATE == OperationInformation->Operation)
	{

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_OPERATION))
			ClearFlag(OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
				PROCESS_VM_OPERATION);

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_READ))
			ClearFlag(OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
				PROCESS_VM_READ);

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_WRITE))
			ClearFlag(OperationInformation->Parameters->CreateHandleInformation.DesiredAccess,
				PROCESS_VM_WRITE);

		if (FlagOn(OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess,
			PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE))
		{
			/*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->Handle duplicate ProcessId = %I64d ProcessName = %ws RequestProcessId = %I64d Kernel = %d access denied.\n",
					__FUNCTION__,
					(LONGLONG)ProcessId,
					NULL != OutProcessInfo->OwnedProcessRule ?
					OutProcessInfo->OwnedProcessRule->ProcessName : NULL,
					(LONGLONG)RequestProcessId,
					OperationInformation->KernelHandle));*/
		}
			
	}

EXIT:

	if (NULL != RequestEProcess)
	{
		ObDereferenceObject(RequestEProcess);
		RequestEProcess = NULL;
	}

	if (NULL != uProcessName)
	{
		ExFreePool(uProcessName);
		uProcessName = NULL;
	}

	Status = OB_PREOP_SUCCESS;

	return Status;
}


VOID PocProcessNotifyRoutineEx(
	IN PEPROCESS Process,
	IN HANDLE ProcessId,
	IN PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(CreateInfo);

	NTSTATUS Status = 0;
	PUNICODE_STRING uProcessName = NULL;

	PPOC_PROCESS_RULES OutProcessRules = NULL;
	PPOC_CREATED_PROCESS_INFO OutProcessInfo = NULL;

	Status = SeLocateProcessImageName(Process, &uProcessName);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->SeLocateProcessImageName EProcess = %p failed. Status = 0x%x.\n",
				__FUNCTION__, Process, Status));

		goto EXIT;
	}


	Status = PocFindProcessRulesNodeByName(
		uProcessName->Buffer,
		&OutProcessRules,
		FALSE);

	if (STATUS_SUCCESS != Status)
	{
		goto EXIT;
	}


	if (NULL == CreateInfo)
	{

		PocFindProcessInfoNodeByPid(
			ProcessId,
			OutProcessRules,
			NULL,
			TRUE);

		if (STATUS_SUCCESS != Status)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->PocFindProcessInfoNodeByPid ProcessName = %ws ProcessId = %I64d failed. Status = 0x%x.\n",
					__FUNCTION__,
					uProcessName->Buffer,
					(LONGLONG)ProcessId,
					Status));

			goto EXIT;
		}

	}
	else
	{


		Status = PocCreateProcessInfoNode(
			OutProcessRules,
			&OutProcessInfo);

		if (STATUS_SUCCESS != Status)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->PocCreateProcessInfoNode ProcessName = %ws failed. Status = 0x%x.\n",
					__FUNCTION__,
					uProcessName->Buffer,
					Status));

			goto EXIT;
		}

		OutProcessInfo->ProcessId = ProcessId;

		/*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->Add ProcessName = %ws ProcessId = %I64d Access = %d success.\n",
				__FUNCTION__,
				uProcessName->Buffer,
				(LONGLONG)ProcessId,
				OutProcessRules->Access));*/


		
	}

EXIT:

	if (NULL != uProcessName)
	{
		ExFreePool(uProcessName);
		uProcessName = NULL;
	}

	return;
}


VOID PocLoadImageNotifyRoutine(
	IN PUNICODE_STRING FullImageName,
	IN HANDLE ProcessId,
	IN PIMAGE_INFO ImageInfo)
{
	UNREFERENCED_PARAMETER(FullImageName);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ImageInfo);

	if (0 == ProcessId)
	{
		return;
	}

	PAGED_CODE();

	NTSTATUS Status = 0;
	PPOC_CREATED_PROCESS_INFO OutProcessInfo = NULL;

	Status = PocFindProcessInfoNodeByPidEx(ProcessId, &OutProcessInfo, FALSE, FALSE);

	if (STATUS_SUCCESS != Status)
	{
		goto EXIT;
	}

	if (FALSE == OutProcessInfo->ThreadStartUp)
	{
		OutProcessInfo->ThreadStartUp = TRUE;
	}

EXIT:

	return;
}


NTSTATUS PocProcessObjectCallbackInit()
{
	NTSTATUS Status = 0;

	OB_CALLBACK_REGISTRATION ObCallbackRegistration = { 0 };
	OB_OPERATION_REGISTRATION ObOperationRegistration[2] = { 0 };


	ObOperationRegistration[0].ObjectType = PsProcessType;
	ObOperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	ObOperationRegistration[0].PreOperation = (POB_PRE_OPERATION_CALLBACK)(&PocPreObjectOperation);

	ObOperationRegistration[1].ObjectType = PsThreadType;
	ObOperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	ObOperationRegistration[1].PreOperation = (POB_PRE_OPERATION_CALLBACK)(&PocPreObjectOperation);


	ObCallbackRegistration.Version = ObGetFilterVersion();
	ObCallbackRegistration.OperationRegistrationCount = 2;
	ObCallbackRegistration.RegistrationContext = NULL;
	RtlInitUnicodeString(&ObCallbackRegistration.Altitude, L"141001");
	ObCallbackRegistration.OperationRegistration = ObOperationRegistration;

	Status = ObRegisterCallbacks(&ObCallbackRegistration, &gObjectHandle);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ObRegisterCallbacks failed. Status = 0x%x.\n",
			__FUNCTION__,
			Status));

		goto EXIT;
	}

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("%s->ObRegisterCallbacks register process and thread object success.\n", __FUNCTION__));

EXIT:

	return Status;
}


NTSTATUS PocInitProcess()
{
	NTSTATUS Status = 0;

	PCHAR SystemInfomation = NULL;
	ULONG SystemInformationLength = 0;
	ULONG ReturnedLength = 0;

	PSYSTEM_PROCESS_INFORMATION ProcessInfo = NULL;
	ULONG TotalOffset = 0;

	PEPROCESS EProcess = NULL;
	PUNICODE_STRING uProcessName = NULL;

	PPOC_PROCESS_RULES OutProcessRules = NULL;
	PPOC_CREATED_PROCESS_INFO OutProcessInfo = NULL;

	HANDLE ThreadHandle = NULL;


	Status = PocProcessRulesListInit();

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
			("%s->PocProcessRulesListInit failed. Status = 0x%x.", __FUNCTION__, Status));
		goto EXIT;
	}


	/*Status = PocProcessObjectCallbackInit();

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PocProcessObjectCallbackInit failed. Status = 0x%x.", __FUNCTION__, Status));
		goto EXIT;
	}*/
	

	Status = PsSetCreateProcessNotifyRoutineEx(
		PocProcessNotifyRoutineEx,
		FALSE);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
			("%s->PsSetCreateProcessNotifyRoutineEx failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}

	/*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
		("%s->PsSetCreateProcessNotifyRoutineEx init success.\n", __FUNCTION__));*/


	/*
	* 遍历一下PsSetCreateProcessNotifyRoutineEx监控之前就创建的进程，
	* 把属于ProcessRules的进程加入到链表中
	*/

	Status = NtQuerySystemInformation(
		SystemProcessInformation, 
		SystemInfomation, 
		SystemInformationLength, 
		&ReturnedLength);

	if (STATUS_SUCCESS != Status && STATUS_INFO_LENGTH_MISMATCH != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->NtQuerySystemInformation1 failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}

	SystemInformationLength = ReturnedLength * 2;

	SystemInfomation = ExAllocatePoolWithTag(
		NonPagedPool,
		SystemInformationLength,
		POC_PR_LIST_TAG);

	if (NULL == SystemInfomation)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag SystemInfomation failed.\n", __FUNCTION__));
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto EXIT;
	}

	RtlZeroMemory(SystemInfomation, SystemInformationLength);

	Status = NtQuerySystemInformation(
		SystemProcessInformation,
		SystemInfomation,
		SystemInformationLength,
		&ReturnedLength);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->NtQuerySystemInformation2 failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}

	ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInfomation;

	while (TRUE)
	{

		Status = PsLookupProcessByProcessId(ProcessInfo->UniqueProcessId, &EProcess);

		if (!NT_SUCCESS(Status))
		{
			if(0 != ProcessInfo->UniqueProcessId)
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PsLookupProcessByProcessId UniqueProcessId = %I64d failed. Status = 0x%x.\n",
					__FUNCTION__,
					(LONGLONG)ProcessInfo->UniqueProcessId,
					Status));

			goto ERROR;
		}

		Status = SeLocateProcessImageName(EProcess, &uProcessName);

		if (!NT_SUCCESS(Status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->SeLocateProcessImageName EProcess = %p failed. Status = 0x%x.\n",
					__FUNCTION__, EProcess, Status));

			goto ERROR;
		}


		Status = PocFindProcessRulesNodeByName(
			uProcessName->Buffer,
			&OutProcessRules,
			FALSE);

		if (STATUS_SUCCESS != Status)
		{
			goto ERROR;
		}

		Status = PocCreateProcessInfoNode(
			OutProcessRules,
			&OutProcessInfo);

		if (STATUS_SUCCESS != Status)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("%s->PocCreateProcessInfoNode ProcessName = %ws failed. Status = 0x%x.\n",
					__FUNCTION__,
					uProcessName->Buffer,
					Status));

			goto ERROR;
		}

		OutProcessInfo->ProcessId = ProcessInfo->UniqueProcessId;

		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->Add ProcessName = %ws ProcessId = %I64d Access = %d success.\n",
				__FUNCTION__,
				uProcessName->Buffer,
				(LONGLONG)ProcessInfo->UniqueProcessId,
				OutProcessRules->Access));


ERROR:
		if (NULL != EProcess)
		{
			ObDereferenceObject(EProcess);
			EProcess = NULL;
		}

		if (NULL != uProcessName)
		{
			ExFreePool(uProcessName);
			uProcessName = NULL;
		}

		OutProcessRules = NULL;
		OutProcessInfo = NULL;

		if (ProcessInfo->NextEntryOffset == 0) 
		{
			break;
		}
		else 
		{
			TotalOffset += ProcessInfo->NextEntryOffset;
			ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)&SystemInfomation[TotalOffset];
		}

	}



	Status = PsSetLoadImageNotifyRoutine(
		PocLoadImageNotifyRoutine);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
			("%s->PsSetLoadImageNotifyRoutine failed. Status = 0x%x.\n", __FUNCTION__, Status));
		goto EXIT;
	}

	/*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("%s->PsSetLoadImageNotifyRoutine init success.\n", __FUNCTION__));*/


	/*
	* 进程.text完整性检查
	*/

	Status = PsCreateSystemThread(
		&ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		PocProcessIntegrityCheckThread,
		NULL);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PsCreateSystemThread PocProcessIntegrityCheckThread failed. Status = 0x%x.\n",
				__FUNCTION__,
				Status));

		goto EXIT;
	}

	/*PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("%s->PsCreateSystemThread PocProcessIntegrityCheckThread init success.\n", __FUNCTION__));*/

	if (NULL != ThreadHandle)
	{
		ZwClose(ThreadHandle);
		ThreadHandle = NULL;
	}


	if (NULL != SystemInfomation)
	{
		ExFreePoolWithTag(SystemInfomation, POC_PR_LIST_TAG);
		SystemInfomation = NULL;
	}

	return Status;

EXIT:


	PocProcessCleanup();

	return Status;
}


VOID PocProcessCleanup()
{
	NTSTATUS Status = 0;
	LARGE_INTEGER Interval = { 0 };


	Status = PsSetCreateProcessNotifyRoutineEx(
		PocProcessNotifyRoutineEx,
		TRUE);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
			("%s->PsSetCreateProcessNotifyRoutineEx Remove failed. Status = 0x%x.\n", __FUNCTION__, Status));
	}

	Status = PsRemoveLoadImageNotifyRoutine(
		PocLoadImageNotifyRoutine);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
			("%s->PsRemoveLoadImageNotifyRoutine failed. Status = 0x%x.\n", __FUNCTION__, Status));
	}


	if (NULL != gObjectHandle)
	{
		ObUnRegisterCallbacks(gObjectHandle);
		gObjectHandle = NULL;
	}

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("%s->Wait 12 seconds for PocProcessIntegrityCheckThread to exit. \n", __FUNCTION__));

	Interval.QuadPart = -120 * 1000 * 1000;

	Status = KeDelayExecutionThread(KernelMode, FALSE, &Interval);


	PocProcessRulesListCleanup();

}
