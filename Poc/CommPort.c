
#include "commport.h"
#include "utils.h"
#include "filefuncs.h"
#include "process.h"

PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;

PCHAR ReplyBuffer = NULL;

NTSTATUS PocConnectNotifyCallback(
	IN PFLT_PORT ClientPort,
	IN PVOID ServerPortCookie,
	IN PVOID ConnectionContext,
	IN ULONG SizeOfContext,
	IN PVOID *ConnectionPortCookie)
{

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionPortCookie);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("\nPocConnectNotifyCallback->connect with user.\n"));

	gClientPort = ClientPort;

	ReplyBuffer = ExAllocatePoolWithTag(NonPagedPool, MESSAGE_SIZE, POC_MESSAGE_TAG);

	if (NULL == ReplyBuffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag ReplyBuffer failed.\n", __FUNCTION__));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(ReplyBuffer, MESSAGE_SIZE);

	return STATUS_SUCCESS;
}


VOID PocDisconnectNotifyCallback(
	IN PVOID ConnectionCookie)
{

	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocDisconnectNotifyCallback->disconnect with user.\n\n"));

	if (NULL != ReplyBuffer)
	{
		ExFreePoolWithTag(ReplyBuffer, POC_MESSAGE_TAG);
		ReplyBuffer = NULL;
	}

	FltCloseClientPort(gFilterHandle, &gClientPort);
}


NTSTATUS PocMessageNotifyCallback(
	IN PVOID PortCookie,
	IN PVOID InputBuffer,
	IN ULONG InputBufferLength,
	IN PVOID OutputBuffer,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnOutputBufferLength)
/* 
* InputBuffer和ReplyBuffer不能指向一块内存
*/
{

	UNREFERENCED_PARAMETER(PortCookie);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(ReturnOutputBufferLength);

	PAGED_CODE();

	PCHAR Buffer = NULL;
	POC_MESSAGE_HEADER MessageHeader = {0};
	NTSTATUS Status = STATUS_SUCCESS;

	UNICODE_STRING uDosName = {0};

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

				Status = MessageHeader.Command;

				break;
			}
			case POC_PRIVILEGE_ENCRYPT:
			case POC_PRIVILEGE_DECRYPT:
			{
				/*
				 * 特权加密和特权解密，从桌面传命令进驱动
				 */
				CHAR TempFileName[POC_MAX_NAME_LENGTH] = {0};
				WCHAR wFileName[POC_MAX_NAME_LENGTH] = {0};
				ANSI_STRING Ansi = {0};
				UNICODE_STRING uFileName = {0};
				PWCHAR lpFileName = NULL;

				WCHAR wSymbolLinkName[POC_MAX_NAME_LENGTH] = {0};
				UNICODE_STRING uSymbolLinkName = {0};

				PFLT_INSTANCE Instance = NULL;

				WCHAR FileExtension[POC_MAX_NAME_LENGTH] = { 0 };

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
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
						("%s->POC_PRIVILEGE_DECRYPT->RtlAnsiStringToUnicodeString failed status = 0x%x.\n", 
							__FUNCTION__, Status));
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
				uSymbolLinkName.MaximumLength = sizeof(wSymbolLinkName);


				Status = PocQuerySymbolicLink(
					&uSymbolLinkName,
					&uDosName);

				if (STATUS_SUCCESS != Status)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
						("%s->POC_PRIVILEGE_DECRYPT->PocQuerySymbolicLink failed ststus = 0x%x.\n", 
							__FUNCTION__, Status));
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

				Status = PocParseFileNameExtension(
					uFileName.Buffer, 
					FileExtension);

				if (STATUS_SUCCESS != Status)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocParseFileNameExtension failed.\n", __FUNCTION__));
					goto EXIT;
				}

				Status = PocBypassIrrelevantFileExtension(
					FileExtension);

				if (POC_IS_TARGET_FILE_EXTENSION != Status)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
						("%s->PocBypassIrrelevantFileExtension failed. Irrelevent file extension\n", __FUNCTION__));
					goto EXIT;
				}


				Status = PocFindOrCreateStreamContextOutsite(
					Instance, 
					uFileName.Buffer, 
					TRUE);

				if (STATUS_SUCCESS != Status)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocFindOrCreateStreamContextOutsite failed.\n", __FUNCTION__));
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


				Status = MessageHeader.Command;

				break;
			}
			case POC_ADD_PROCESS_RULES:
			{
				/*
				* 桌面添加进程规则，
				* 这里正常应该遍历所有进程，将已经启动的“属于新添加进程规则”的进程加进链表中，
				* 但是PocMessageNotifyCallback这个函数比较特殊，它内存的mode不太对，
				* 所以调用遍历函数NtQuerySystemInformation会失败。
				*/
				PPOC_PROCESS_RULES ProcessRules = NULL;

				ANSI_STRING aProcessName = {0};
				UNICODE_STRING uProcessName = {0};
				WCHAR ProcessName[POC_MAX_NAME_LENGTH] = {0};
				WCHAR DosProcessName[POC_MAX_NAME_LENGTH] = {0};

				if (0 == strlen(((PPOC_MESSAGE_PROCESS_RULES)(Buffer + sizeof(POC_MESSAGE_HEADER)))->ProcessName))
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ProcessName is null.\n", __FUNCTION__));
					Status = STATUS_INVALID_PARAMETER;
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

				Status = PocAnyPath2DosPath(ProcessName, DosProcessName, sizeof(DosProcessName));

				if (STATUS_SUCCESS != Status)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocAnyPath2DosPath failed. Status = 0x%x.\n", __FUNCTION__, Status));
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

				Status = MessageHeader.Command;

				break;
			}
			case POC_ADD_SECURE_FODER:
			{
				/*
				* 添加机密文件夹
				*/

				if (0 == strlen(((PPOC_MESSAGE_SECURE_FODER)(Buffer + sizeof(POC_MESSAGE_HEADER)))->SecureFolder))
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Extension is null.\n", __FUNCTION__));
					Status = STATUS_INVALID_PARAMETER;
					goto EXIT;
				}

				WCHAR SecureFolder[POC_MAX_NAME_LENGTH] = {0};
				WCHAR DosSecureFolder[POC_MAX_NAME_LENGTH] = { 0 };

				Status = PocAnsi2Unicode(
					((PPOC_MESSAGE_SECURE_FODER)(Buffer + sizeof(POC_MESSAGE_HEADER)))->SecureFolder,
					SecureFolder,
					POC_MAX_NAME_LENGTH);

				if (Status != STATUS_SUCCESS)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocAnsi2Unicode failed. Status = 0x%x.\n", __FUNCTION__, Status));
					goto EXIT;
				}

				Status = PocAnyPath2DosPath(
					SecureFolder, 
					DosSecureFolder, 
					sizeof(DosSecureFolder));

				if (Status != STATUS_SUCCESS)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocAnyPath2DosPath failed. Status = 0x%x.\n", 
						__FUNCTION__, Status));
					goto EXIT;
				}

				Status = PocAddOrFindRelevantPath(DosSecureFolder, FALSE);

				if (Status != STATUS_SUCCESS)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocAddOrFindRelevantPath failed. Status = 0x%x.\n", __FUNCTION__, Status));
					goto EXIT;
				}

				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Add secure folder success. Folder = %ws.\n", __FUNCTION__,
					SecureFolder));

				Status = MessageHeader.Command;

				break;
			}
			case POC_ADD_SECURE_EXTENSION:
			{
				/*
				* 添加需管控的文件扩展名
				*/

				if (0 == strlen(((PPOC_MESSAGE_SECURE_EXTENSION)(Buffer + sizeof(POC_MESSAGE_HEADER)))->Extension))
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Extension is null.\n", __FUNCTION__));
					Status = STATUS_INVALID_PARAMETER;
					goto EXIT;
				}

				Status = PocAddSecureExtension(
					((PPOC_MESSAGE_SECURE_EXTENSION)(Buffer + sizeof(POC_MESSAGE_HEADER)))->Extension);

				if (Status != STATUS_SUCCESS)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->PocAddSecureExtension failed. Status = 0x%x.\n", __FUNCTION__, Status));
					goto EXIT;
				}

				Status = MessageHeader.Command;

				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Add file extension success. Extension = %s.\n", __FUNCTION__,
					((PPOC_MESSAGE_SECURE_EXTENSION)(Buffer + sizeof(POC_MESSAGE_HEADER)))->Extension));

				break;
			}
			case POC_GET_PROCESS_RULES:
			{
				/*
				* 遍历进程规则，回传到User
				*/
				PPOC_PROCESS_RULES ProcessRules = { 0 };
				PLIST_ENTRY pListEntry = PocProcessRulesListHead.Flink;

				ULONG Index = 0;

				RtlZeroMemory(ReplyBuffer, MESSAGE_SIZE);

				while (pListEntry != &PocProcessRulesListHead)
				{

					ProcessRules = CONTAINING_RECORD(pListEntry, POC_PROCESS_RULES, ListEntry);

					if (((PPOC_MESSAGE_HEADER)ReplyBuffer)->Length <= MESSAGE_SIZE - sizeof(POC_MESSAGE_HEADER))
					{
						Status = RtlUnicodeToMultiByteN(
							((PPOC_MESSAGE_PROCESS_RULES)(ReplyBuffer + sizeof(POC_MESSAGE_HEADER) +
								((PPOC_MESSAGE_HEADER)ReplyBuffer)->Length))->ProcessName,
							POC_MAX_NAME_LENGTH,
							&Index,
							ProcessRules->ProcessName,
							(ULONG)wcslen(ProcessRules->ProcessName) * sizeof(WCHAR));

						if (Status != STATUS_SUCCESS)
						{
							PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
								("%s->RtlUnicodeToMultiByteN PR failed. Status = 0x%x.\n", __FUNCTION__, Status));
							goto EXIT;
						}

						((PPOC_MESSAGE_PROCESS_RULES)(ReplyBuffer + sizeof(POC_MESSAGE_HEADER) +
							((PPOC_MESSAGE_HEADER)ReplyBuffer)->Length))->Access = ProcessRules->Access;

						((PPOC_MESSAGE_HEADER)ReplyBuffer)->Length += sizeof(POC_MESSAGE_PROCESS_RULES);
					}
					else
					{
						Status = POC_GET_PROCESS_RULES;
						goto EXIT;
					}
					

					pListEntry = pListEntry->Flink;
				}

				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Get process rules success. PR Count = %d.\n", __FUNCTION__,
					((PPOC_MESSAGE_HEADER)ReplyBuffer)->Length / sizeof(POC_MESSAGE_PROCESS_RULES)));

				Status = MessageHeader.Command;

				break;
			}
			case POC_GET_FILE_EXTENSION:
			{
				/*
				* 遍历文件扩展名，回传到User
				*/
				ULONG Index = 0;

				RtlZeroMemory(ReplyBuffer, MESSAGE_SIZE);

				for (ULONG i = 0; i < secure_extension_count; i++)
				{
					Status = RtlUnicodeToMultiByteN(
						((PPOC_MESSAGE_SECURE_EXTENSION)(ReplyBuffer + sizeof(POC_MESSAGE_HEADER) +
							((PPOC_MESSAGE_HEADER)ReplyBuffer)->Length))->Extension,
						POC_EXTENSION_SIZE,
						&Index,
						secure_extension[i],
						(ULONG)wcslen(secure_extension[i]) * sizeof(WCHAR));

					if (Status != STATUS_SUCCESS)
					{
						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
							("%s->RtlUnicodeToMultiByteN Ext failed. Status = 0x%x.\n", __FUNCTION__, Status));
						goto EXIT;
					}

					((PPOC_MESSAGE_HEADER)ReplyBuffer)->Length += sizeof(POC_MESSAGE_SECURE_EXTENSION);
				}

				Status = MessageHeader.Command;

				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Get file extension success. Ext Count = %d.\n", __FUNCTION__,
					((PPOC_MESSAGE_HEADER)ReplyBuffer)->Length / sizeof(POC_MESSAGE_SECURE_EXTENSION)));

				break;
			}
			case POC_REMOVE_FILE_EXTENSION:
			{
				/*
				* 移除文件扩展名
				*/
				WCHAR wExtension[POC_EXTENSION_SIZE] = { 0 };
				ULONG Index = 0;

				Status = RtlMultiByteToUnicodeN(
					wExtension,
					sizeof(wExtension), 
					&Index,
					((PPOC_MESSAGE_SECURE_EXTENSION)(Buffer + sizeof(POC_MESSAGE_HEADER)))->Extension,
					(ULONG)strlen(((PPOC_MESSAGE_SECURE_EXTENSION)
						(Buffer + sizeof(POC_MESSAGE_HEADER)))->Extension));

				if (Status != STATUS_SUCCESS)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
						("%s->RtlMultiByteToUnicodeN Ext = %s failed. Status = 0x%x.\n", 
							__FUNCTION__, 
							((PPOC_MESSAGE_SECURE_EXTENSION)(Buffer + sizeof(POC_MESSAGE_HEADER)))->Extension, 
							Status));

					goto EXIT;
				}

				Status = POC_OBJECT_NOT_FOUND;

				for (ULONG i = 0; i < secure_extension_count; i++)
				{
					if (_wcsnicmp(wExtension, secure_extension[i], wcslen(secure_extension[i])) == 0)
					{
						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
							("%s->Remove file extension success. Ext = %ws.\n", 
							__FUNCTION__,
							wExtension));

						for (ULONG j = i; j < secure_extension_count; j++)
						{
							RtlZeroMemory(
								secure_extension[j],
								POC_EXTENSION_SIZE);

							wcsncpy(secure_extension[j], secure_extension[j + 1], wcslen(secure_extension[j + 1]));
						}

						RtlZeroMemory(
							secure_extension[secure_extension_count], 
							POC_EXTENSION_SIZE);

						secure_extension_count--;

						Status = MessageHeader.Command;
						break;
					}
				}

				break;
			}
			case POC_GET_SECURE_FOLDER:
			{
				/*
				* 遍历机密文件夹，回传到User
				*/
				ULONG Index = 0;

				RtlZeroMemory(ReplyBuffer, MESSAGE_SIZE);

				for (ULONG i = 0; i < current_relevant_path_inx; i++)
				{
					Status = RtlUnicodeToMultiByteN(
						((PPOC_MESSAGE_SECURE_FODER)(ReplyBuffer + sizeof(POC_MESSAGE_HEADER) +
							((PPOC_MESSAGE_HEADER)ReplyBuffer)->Length))->SecureFolder,
						POC_MAX_NAME_LENGTH,
						&Index,
						RelevantPath[i],
						(ULONG)wcslen(RelevantPath[i]) * sizeof(WCHAR));

					if (Status != STATUS_SUCCESS)
					{
						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
							("%s->RtlUnicodeToMultiByteN Folder failed. Status = 0x%x.\n", __FUNCTION__, Status));
						goto EXIT;
					}

					((PPOC_MESSAGE_HEADER)ReplyBuffer)->Length += sizeof(POC_MESSAGE_SECURE_FODER);
				}

				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Get all folders success. Folder count = %d current = %d.\n", __FUNCTION__,
					((PPOC_MESSAGE_HEADER)ReplyBuffer)->Length / sizeof(POC_MESSAGE_SECURE_FODER), current_relevant_path_inx));

				Status = MessageHeader.Command;
				break;
			}
			case POC_REMOVE_SECURE_FOLDER:
			{
				/*
				* 移除机密文件夹
				*/
				WCHAR wFolder[POC_MAX_NAME_LENGTH] = { 0 };
				ULONG Index = 0;

				Status = RtlMultiByteToUnicodeN(
					wFolder,
					sizeof(wFolder),
					&Index,
					((PPOC_MESSAGE_SECURE_FODER)(Buffer + sizeof(POC_MESSAGE_HEADER)))->SecureFolder,
					(ULONG)strlen(((PPOC_MESSAGE_SECURE_FODER)
						(Buffer + sizeof(POC_MESSAGE_HEADER)))->SecureFolder));

				if (Status != STATUS_SUCCESS)
				{
					PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
						("%s->RtlMultiByteToUnicodeN Folder = %s failed. Status = 0x%x.\n",
							__FUNCTION__,
							((PPOC_MESSAGE_SECURE_FODER)(Buffer + sizeof(POC_MESSAGE_HEADER)))->SecureFolder,
							Status));

					goto EXIT;
				}

				Status = POC_OBJECT_NOT_FOUND;

				for (ULONG i = 0; i < current_relevant_path_inx; i++)
				{
					if (_wcsnicmp(wFolder, RelevantPath[i], wcslen(RelevantPath[i])) == 0)
					{
						PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
							("%s->Remove secure folder success. Ext = %ws.\n",
								__FUNCTION__,
								wFolder));

						for (ULONG j = i; j < current_relevant_path_inx; j++)
						{
							RtlZeroMemory(
								RelevantPath[j],
								POC_MAX_NAME_LENGTH);

							wcsncpy(RelevantPath[j], RelevantPath[j + 1], wcslen(RelevantPath[j + 1]));
						}

						RtlZeroMemory(
							RelevantPath[current_relevant_path_inx],
							POC_MAX_NAME_LENGTH);

						current_relevant_path_inx--;

						Status = MessageHeader.Command;
						break;
					}
				}

				break;
			}
			default:
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->error command =  0x%x.\n", __FUNCTION__, MessageHeader.Command));
				Status = MessageHeader.Command;
				break;
			}
			}
		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Except 0x%x.\n", __FUNCTION__, GetExceptionCode()));
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

	((PPOC_MESSAGE_HEADER)ReplyBuffer)->Command = Status;

	Status = FltSendMessage(gFilterHandle, &gClientPort, ReplyBuffer, MESSAGE_SIZE, NULL, NULL, NULL);

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
