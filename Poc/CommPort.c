
#include "commport.h"
#include "utils.h"
#include "filefuncs.h"
#include "process.h"

PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;


NTSTATUS PocConnectNotifyCallback(
	IN PFLT_PORT ClientPort, 
	IN PVOID ServerPortCookie, 
	IN PVOID ConnectionContext, 
	IN ULONG SizeOfContext, 
	IN PVOID* ConnectionPortCookie)
{

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionPortCookie);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocConnectNotifyCallback->connect with user.\n"));

	gClientPort = ClientPort;

	return STATUS_SUCCESS;
}


VOID PocDisconnectNotifyCallback(
	IN PVOID ConnectionCookie)
{

	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocDisconnectNotifyCallback->disconnect with user.\n"));

	FltCloseClientPort(gFilterHandle, &gClientPort);
}


NTSTATUS PocMessageNotifyCallback(
	IN PVOID PortCookie,
	IN PVOID InputBuffer,
	IN ULONG InputBufferLength,
	IN PVOID OutputBuffer,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnOutputBufferLength)
{

	UNREFERENCED_PARAMETER(PortCookie);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(ReturnOutputBufferLength);

	PAGED_CODE();

	PCHAR Buffer = NULL;
	POC_MESSAGE_HEADER MessageHeader = { 0 };
	NTSTATUS Status = STATUS_SUCCESS;

	UNICODE_STRING uDosName = { 0 };

	if (InputBuffer != NULL)
	{

		try
		{
			Buffer = InputBuffer;
			
			RtlMoveMemory(&MessageHeader, Buffer, sizeof(POC_MESSAGE_HEADER));

			switch (MessageHeader.Command)
			{
			case POC_HELLO_KERNEL:
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s", (Buffer + sizeof(POC_MESSAGE_HEADER))));
				break;
			}
			case POC_PRIVILEGE_ENCRYPT:
			case POC_PRIVILEGE_DECRYPT:
			{
				/*
				* 特权加密和特权解密，从桌面传命令进驱动
				*/
				CHAR TempFileName[POC_MAX_NAME_LENGTH] = { 0 };
				WCHAR wFileName[POC_MAX_NAME_LENGTH] = { 0 };
				ANSI_STRING Ansi = { 0 };
				UNICODE_STRING uFileName = { 0 };
				PWCHAR lpFileName = NULL;

				WCHAR wSymbolLinkName[POC_MAX_NAME_LENGTH] = { 0 };
				UNICODE_STRING uSymbolLinkName = { 0 };

				PFLT_INSTANCE Instance = NULL;

				RtlMoveMemory(TempFileName, "\\??\\", strlen("\\??\\"));

				if (POC_MAX_NAME_LENGTH - strlen(TempFileName) >= 
					strlen(Buffer + sizeof(POC_MESSAGE_HEADER)))
				{
					RtlMoveMemory(
						TempFileName + strlen(TempFileName),
						Buffer + sizeof(POC_MESSAGE_HEADER),
						strlen(Buffer + sizeof(POC_MESSAGE_HEADER)));
				}
				
				RtlInitAnsiString(&Ansi, TempFileName);

				uFileName.Buffer = wFileName;
				uFileName.MaximumLength = POC_MAX_NAME_LENGTH * sizeof(WCHAR);
				Status = RtlAnsiStringToUnicodeString(&uFileName, &Ansi, FALSE);

				if (STATUS_SUCCESS != Status)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocMessageNotifyCallback->POC_PRIVILEGE_DECRYPT->RtlAnsiStringToUnicodeString failed status = 0x%x.\n", Status));
					goto EXIT;
				}

				/*
				* 把文件的符号链接名转换为Dos名
				*/

				lpFileName = uFileName.Buffer;

				while (*lpFileName != L':' && 
					lpFileName < uFileName.Buffer + wcslen(uFileName.Buffer))
				{
					lpFileName++;
				}

				RtlMoveMemory(
					wSymbolLinkName, 
					uFileName.Buffer, 
					(lpFileName - uFileName.Buffer + 1) * sizeof(WCHAR));

				RtlInitUnicodeString(&uSymbolLinkName, wSymbolLinkName);

				Status = PocQuerySymbolicLink(
					&uSymbolLinkName, 
					&uDosName);

				if (STATUS_SUCCESS != Status)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->POC_PRIVILEGE_DECRYPT->PocQuerySymbolicLink failed ststus = 0x%x.\n", __FUNCTION__, Status));
					goto EXIT;
				}

				Status = PocGetVolumeInstance(
					gFilterHandle,
					&uDosName,
					&Instance);

				if (STATUS_SUCCESS != Status && NULL != Instance)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocGetVolumeInstance failed.\n", __FUNCTION__));
					goto EXIT;
				}

				if (POC_PRIVILEGE_DECRYPT == MessageHeader.Command)
				{
					Status = PocReentryToDecrypt(
						Instance,
						uFileName.Buffer);

					if (STATUS_SUCCESS != Status)
					{
						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocMessageNotifyCallback->PocReentryToDecrypt failed.\n"));
						goto EXIT;
					}
				}
				else
				{
					Status = PocReentryToEncrypt(
						Instance,
						uFileName.Buffer);

					if (STATUS_SUCCESS != Status)
					{
						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocMessageNotifyCallback->PocReentryToDecrypt failed.\n"));
						goto EXIT;
					}
				}

				break;
			}
			case POC_ADD_PROCESS_RULES:
			{
				/*
				* 桌面添加进程规则
				*/
				PPOC_PROCESS_RULES ProcessRules = NULL;

				ANSI_STRING aProcessName = { 0 };
				UNICODE_STRING uProcessName = { 0 };
				WCHAR ProcessName[POC_MAX_NAME_LENGTH] = { 0 };
				WCHAR DosProcessName[POC_MAX_NAME_LENGTH] = { 0 };

				if (NULL == ((PPOC_MESSAGE_PROCESS_RULES)(Buffer + sizeof(POC_MESSAGE_HEADER)))->ProcessName)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ProcessName is null.\n", __FUNCTION__));
					Status =  STATUS_INVALID_PARAMETER;
					goto EXIT;
				}

				aProcessName.Buffer = ((PPOC_MESSAGE_PROCESS_RULES)(Buffer + sizeof(POC_MESSAGE_HEADER)))->ProcessName;
				aProcessName.Length = (USHORT)strlen(aProcessName.Buffer);
				aProcessName.MaximumLength = POC_MAX_NAME_LENGTH;

				uProcessName.Buffer = ProcessName;
				uProcessName.MaximumLength = sizeof(ProcessName);

				Status = RtlAnsiStringToUnicodeString(&uProcessName, &aProcessName, FALSE);

				if (STATUS_SUCCESS != Status)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
						("%s->RtlAnsiStringToUnicodeString failed. Status = 0x%x.\n", 
							__FUNCTION__, Status));

					goto EXIT;
				}

				Status = PocSymbolLinkPathToDosPath(ProcessName, DosProcessName);

				if (STATUS_SUCCESS != Status)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocSymbolLinkPathToDosPath failed. Status = 0x%x.\n", __FUNCTION__, Status));
					goto EXIT;
				}


				Status = PocFindProcessRulesNodeByName(
					DosProcessName,
					NULL,
					TRUE);

				Status = PocCreateProcessRulesNode(&ProcessRules);

				if (STATUS_SUCCESS != Status)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocCreateProcessRulesNode failed. Status = 0x%x.\n", __FUNCTION__, Status));
					goto EXIT;
				}

				ProcessRules->Access = ((PPOC_MESSAGE_PROCESS_RULES)(Buffer + sizeof(POC_MESSAGE_HEADER)))->Access;

				wcsncpy(ProcessRules->ProcessName, 
					DosProcessName,
					wcslen(DosProcessName));

				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Add process rules success. DosProcessName = %ws Access = %d.\n", __FUNCTION__,
					ProcessRules->ProcessName,
					ProcessRules->Access));

				Status = STATUS_SUCCESS;

				break;
			}
			default:
			{

			}
			}

		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}

	}

EXIT:			
	if (NULL != uDosName.Buffer)
	{
		ExFreePool(uDosName.Buffer);
		uDosName.Buffer = NULL;
	}

	if (STATUS_SUCCESS == Status)
	{
		Status = 1;
	}
	MessageHeader.Command = Status;
	MessageHeader.Length = 0;

	Status = FltSendMessage(gFilterHandle, &gClientPort, &MessageHeader, sizeof(MessageHeader), NULL, NULL, NULL);

	if (STATUS_SUCCESS != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltSendMessage failed status = 0x%x.\n", __FUNCTION__, Status));
	}
	else
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->FltSendMessage success.\n", __FUNCTION__));
	}


	return Status;
}


NTSTATUS PocInitCommPort()
{

	NTSTATUS Status;
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	UNICODE_STRING CommPortName;
	OBJECT_ATTRIBUTES ObjectAttributes;

	Status = FltBuildDefaultSecurityDescriptor(&SecurityDescriptor, FLT_PORT_ALL_ACCESS);

	if (!NT_SUCCESS(Status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitCommPort->FltBuildDefaultSecurityDescriptor failed. Status = 0x%x\n", Status));
		return Status;
	}

	RtlInitUnicodeString(&CommPortName, L"\\FOKS-TROT");

	InitializeObjectAttributes(
		&ObjectAttributes, 
		&CommPortName, 
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 
		NULL, 
		SecurityDescriptor);

	Status = FltCreateCommunicationPort(
		gFilterHandle, 
		&gServerPort, 
		&ObjectAttributes, 
		NULL, 
		PocConnectNotifyCallback, 
		PocDisconnectNotifyCallback, 
		PocMessageNotifyCallback, 
		1);

	FltFreeSecurityDescriptor(SecurityDescriptor);

	if (!NT_SUCCESS(Status))
	{
		FltCloseCommunicationPort(gServerPort);
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitCommPort->FltCreateCommunicationPort failed. Status = 0x%x.\n", Status));
		return Status;
	}

	return STATUS_SUCCESS;

}


VOID PocCloseCommPort()
{
	if (gServerPort)
	{
		FltCloseCommunicationPort(gServerPort);
	}
}
