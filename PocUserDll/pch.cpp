// pch.cpp: 与预编译标头对应的源文件
#define _CRT_SECURE_NO_WARNINGS
#include "pch.h"

// 当使用预编译的头时，需要使用此源文件，编译才能成功。

#include <Windows.h>
#include <stdio.h>
#include <fltUser.h>
#include <stdlib.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "fltLib.lib")


#define COMMPORTNAME L"\\FOKS-TROT"

#define POC_ADD_PROCESS_RULES		9
#define POC_GET_PROCESS_RULES		5
#define POC_GET_FILE_EXTENSION		6
#define POC_GET_SECURE_FOLDER		10


typedef struct _POC_MESSAGE_HEADER
{
	UINT Command;
	int Length;

}POC_MESSAGE_HEADER, * PPOC_MESSAGE_HEADER;

typedef struct _POC_GET_MESSAGE
{
	FILTER_MESSAGE_HEADER MessageHeader;
	POC_MESSAGE_HEADER Message;

}POC_GET_MESSAGE, * PPOC_GET_MESSAGE;

typedef struct _POC_MESSAGE_PROCESS_RULES
{
	CHAR ProcessName[320];
	ULONG Access;

} POC_MESSAGE_PROCESS_RULES, * PPOC_MESSAGE_PROCESS_RULES;

typedef struct _POC_MESSAGE_SECURE_FODER
{
	CHAR SecureFolder[320];

} POC_MESSAGE_SECURE_FODER, * PPOC_MESSAGE_SECURE_FODER;

typedef struct _POC_MESSAGE_SECURE_EXTENSION
{
	CHAR Extension[32];

} POC_MESSAGE_SECURE_EXTENSION, * PPOC_MESSAGE_SECURE_EXTENSION;

#define MESSAGE_SIZE 4096*10
#define POC_SINGLE_BUFFER_SIZE	400


INT PocUserInitCommPort(IN HANDLE* hPort)
{
	HRESULT hResult;

	hResult = FilterConnectCommunicationPort(COMMPORTNAME, NULL, NULL, NULL, NULL, hPort);

	if (hResult != S_OK)
	{
		return hResult;
	}

	return 0;
}


INT PocUserSendMessage(IN HANDLE hPort, IN LPVOID lpInBuffer, IN INT Command)
{

	if (NULL == lpInBuffer)
	{
		return 1;
	}

	HRESULT hResult;
	DWORD BytesReturned;
	POC_MESSAGE_HEADER MessageHeader = { 0 };

	char* Buffer = (char*)malloc(MESSAGE_SIZE + sizeof(FILTER_MESSAGE_HEADER));

	if (NULL == Buffer)
	{
		return 1;
	}

	memset(Buffer, 0, MESSAGE_SIZE + sizeof(FILTER_MESSAGE_HEADER));

	MessageHeader.Command = Command;
	MessageHeader.Length = strlen((PCHAR)lpInBuffer);

	RtlMoveMemory(Buffer, &MessageHeader, sizeof(MessageHeader));
	RtlMoveMemory(Buffer + sizeof(MessageHeader), lpInBuffer, strlen((PCHAR)lpInBuffer));

	hResult = FilterSendMessage(hPort, Buffer, MESSAGE_SIZE, NULL, NULL, &BytesReturned);


	if (NULL != Buffer)
	{
		free(Buffer);
		Buffer = NULL;
	}

	if (FAILED(hResult))
	{
		return hResult;
	}

	return 0;
}


INT PocUserAddProcessRules(IN HANDLE hPort, IN PCHAR ProcessName, IN UINT Access)
{

	if (NULL == ProcessName)
	{
		return 1;
	}

	HRESULT hResult;
	DWORD BytesReturned;
	POC_MESSAGE_HEADER MessageHeader = { 0 };

	char* Buffer = (char*)malloc(MESSAGE_SIZE + sizeof(FILTER_MESSAGE_HEADER));

	if (NULL == Buffer)
	{
		return 1;
	}

	memset(Buffer, 0, MESSAGE_SIZE + sizeof(FILTER_MESSAGE_HEADER));

	CHAR InBuffer[520] = { 0 };

	MessageHeader.Command = POC_ADD_PROCESS_RULES;
	MessageHeader.Length = 320 + sizeof(UINT);

	strncpy(InBuffer, ProcessName, strlen(ProcessName));
	RtlMoveMemory(InBuffer + 320, (PVOID)&Access, sizeof(Access));

	RtlMoveMemory(Buffer, &MessageHeader, sizeof(MessageHeader));
	RtlMoveMemory(Buffer + sizeof(MessageHeader), InBuffer, 320 + sizeof(UINT));

	hResult = FilterSendMessage(hPort, Buffer, MESSAGE_SIZE, NULL, NULL, &BytesReturned);

	if (NULL != Buffer)
	{
		free(Buffer);
		Buffer = NULL;
	}

	if (FAILED(hResult))
	{
		return hResult;
	}

	return 0;
}


INT PocUserGetMessage(IN HANDLE hPort, IN OUT UINT* Command)
{
	HRESULT hResult = 0;
	OVERLAPPED OverLapped = { 0 };

	char* Buffer = (char*)malloc(MESSAGE_SIZE + sizeof(FILTER_MESSAGE_HEADER));

	if (NULL == Buffer)
	{
		return 1;
	}

	memset(Buffer, 0, MESSAGE_SIZE + sizeof(FILTER_MESSAGE_HEADER));

	while (TRUE)
	{
		hResult = FilterGetMessage(hPort, 
			&((PPOC_GET_MESSAGE)Buffer)->MessageHeader, 
			MESSAGE_SIZE + sizeof(FILTER_MESSAGE_HEADER), 
			&OverLapped);

		Sleep(1000);

		if (((PPOC_GET_MESSAGE)Buffer)->Message.Command != 0)
		{
			*Command = ((PPOC_GET_MESSAGE)Buffer)->Message.Command;
			break;
		}
	}

	if (NULL != Buffer)
	{
		free(Buffer);
		Buffer = NULL;
	}

	return 0;
}


INT PocUserGetMessageEx(IN HANDLE hPort, IN OUT UINT* Command, IN OUT char * MessageBuffer)
{
	HRESULT hResult = 0;
	OVERLAPPED OverLapped = { 0 };

	int ret = 0;

	char* Buffer = (char*)malloc(MESSAGE_SIZE + sizeof(FILTER_MESSAGE_HEADER));

	if (NULL == Buffer)
	{
		return 1;
	}

	memset(Buffer, 0, MESSAGE_SIZE + sizeof(FILTER_MESSAGE_HEADER));
	
	while (TRUE)
	{
		hResult = FilterGetMessage(
			hPort, 
			&((PPOC_GET_MESSAGE)Buffer)->MessageHeader, 
			MESSAGE_SIZE + sizeof(FILTER_MESSAGE_HEADER), 
			&OverLapped);

		Sleep(1000);


		if (((PPOC_GET_MESSAGE)Buffer)->Message.Command != 0)
		{
			for (int i = 0; i < MESSAGE_SIZE -sizeof(POC_MESSAGE_HEADER) - 1; i++)
			{
				if ('\0' == *(Buffer + sizeof(POC_GET_MESSAGE) + i))
				{
					*(Buffer + sizeof(POC_GET_MESSAGE) + i) = ' ';
				}
			}

			RtlMoveMemory(
				MessageBuffer, Buffer + sizeof(POC_GET_MESSAGE),
				((PPOC_GET_MESSAGE)Buffer)->Message.Length);

			if (POC_GET_PROCESS_RULES == ((PPOC_GET_MESSAGE)Buffer)->Message.Command)
			{
				ret = ((PPOC_GET_MESSAGE)Buffer)->Message.Length / sizeof(POC_MESSAGE_PROCESS_RULES);
			}
			else if (POC_GET_FILE_EXTENSION == ((PPOC_GET_MESSAGE)Buffer)->Message.Command)
			{
				ret = ((PPOC_GET_MESSAGE)Buffer)->Message.Length / sizeof(POC_MESSAGE_SECURE_EXTENSION);
			}
			else if (POC_GET_SECURE_FOLDER == ((PPOC_GET_MESSAGE)Buffer)->Message.Command)
			{
				ret = ((PPOC_GET_MESSAGE)Buffer)->Message.Length / sizeof(POC_MESSAGE_SECURE_FODER);
			}

			*Command = ((PPOC_GET_MESSAGE)Buffer)->Message.Command;
			break;
		}
	}

	if (NULL != Buffer)
	{
		free(Buffer);
		Buffer = NULL;
	}

	return ret;
}
