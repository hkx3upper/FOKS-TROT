// pch.cpp: 与预编译标头对应的源文件
#define _CRT_SECURE_NO_WARNINGS
#include "pch.h"

// 当使用预编译的头时，需要使用此源文件，编译才能成功。

#include <Windows.h>
#include <stdio.h>
#include <fltUser.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "fltLib.lib")


#define COMMPORTNAME L"\\FOKS-TROT"

#define POC_ADD_PROCESS_RULES		9


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

#define MESSAGE_SIZE 1024



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
	char Buffer[MESSAGE_SIZE] = { 0 };


	MessageHeader.Command = Command;
	MessageHeader.Length = strlen((PCHAR)lpInBuffer);

	RtlMoveMemory(Buffer, &MessageHeader, sizeof(MessageHeader));
	RtlMoveMemory(Buffer + sizeof(MessageHeader), lpInBuffer, strlen((PCHAR)lpInBuffer));

	hResult = FilterSendMessage(hPort, Buffer, MESSAGE_SIZE, NULL, NULL, &BytesReturned);

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
	char Buffer[MESSAGE_SIZE] = { 0 };

	CHAR InBuffer[520] = { 0 };

	MessageHeader.Command = POC_ADD_PROCESS_RULES;
	MessageHeader.Length = 320 + sizeof(UINT);

	strncpy(InBuffer, ProcessName, strlen(ProcessName));
	RtlMoveMemory(InBuffer + 320, (PVOID)&Access, sizeof(Access));

	RtlMoveMemory(Buffer, &MessageHeader, sizeof(MessageHeader));
	RtlMoveMemory(Buffer + sizeof(MessageHeader), InBuffer, 320 + sizeof(UINT));

	hResult = FilterSendMessage(hPort, Buffer, MESSAGE_SIZE, NULL, NULL, &BytesReturned);

	if (FAILED(hResult))
	{
		return hResult;
	}

	return 0;
}


INT PocUserGetMessage(IN HANDLE hPort, IN UINT* Command)
{
	HRESULT hResult = 0;
	OVERLAPPED OverLapped = { 0 };

	POC_GET_MESSAGE Message = { 0 };


	while (TRUE)
	{
		hResult = FilterGetMessage(hPort, &Message.MessageHeader, sizeof(POC_GET_MESSAGE), &OverLapped);

		Sleep(1000);

		if (Message.Message.Command != 0)
		{
			*Command = Message.Message.Command;
			break;
		}
	}

	return 0;
}
