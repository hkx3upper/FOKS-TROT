
#include "commport.h"
#include "utils.h"
#include "filefuncs.h"

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

	DbgPrint("PocConnectNotifyCallback->connect with user.\n");

	gClientPort = ClientPort;

	return STATUS_SUCCESS;
}


VOID PocDisconnectNotifyCallback(
	IN PVOID ConnectionCookie)
{

	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	DbgPrint("PocDisconnectNotifyCallback->disconnect with user.\n");

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
				DbgPrint("%s", (Buffer + sizeof(POC_MESSAGE_HEADER)));
				break;
			}
			case POC_PRIVILEGE_ENCRYPT:
			case POC_PRIVILEGE_DECRYPT:
			{
				CHAR TempFileName[POC_MAX_NAME_LENGTH] = { 0 };
				WCHAR wFileName[POC_MAX_NAME_LENGTH] = { 0 };
				ANSI_STRING Ansi = { 0 };
				UNICODE_STRING uFileName = { 0 };
				PWCHAR lpFileName = NULL;

				WCHAR wSymbolLinkName[POC_MAX_NAME_LENGTH] = { 0 };
				UNICODE_STRING uSymbolLinkName = { 0 };
				UNICODE_STRING uDosName = { 0 };

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
					DbgPrint("PocMessageNotifyCallback->POC_PRIVILEGE_DECRYPT->RtlAnsiStringToUnicodeString failed status = 0x%x.\n", Status);
					goto EXIT;
				}

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
					DbgPrint("PocMessageNotifyCallback->POC_PRIVILEGE_DECRYPT->PocQuerySymbolicLink failed ststus = 0x%x.\n", Status);
					goto EXIT;
				}

				Status = PocGetVolumeInstance(
					gFilterHandle,
					&uDosName,
					&Instance);

				if (STATUS_SUCCESS != Status)
				{
					DbgPrint("PocMessageNotifyCallback->PocGetVolumeInstance failed.\n");
					goto EXIT;
				}

				if (POC_PRIVILEGE_DECRYPT == MessageHeader.Command)
				{
					Status = PocReentryToDecrypt(
						Instance,
						uFileName.Buffer);

					if (STATUS_SUCCESS != Status)
					{
						DbgPrint("PocMessageNotifyCallback->PocReentryToDecrypt failed.\n");
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
						DbgPrint("PocMessageNotifyCallback->PocReentryToDecrypt failed.\n");
						goto EXIT;
					}
				}




EXIT:			if (NULL != uDosName.Buffer)
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
					DbgPrint("PocMessageNotifyCallback->FltSendMessage failed status = 0x%x.\n", Status);
				}
				else
				{
					DbgPrint("PocMessageNotifyCallback->FltSendMessage success.\n");
				}

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
		DbgPrint("PocInitCommPort->FltBuildDefaultSecurityDescriptor failed. Status = 0x%x\n", Status);
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
		DbgPrint("PocInitCommPort->FltCreateCommunicationPort failed. Status = 0x%x.\n", Status);
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
