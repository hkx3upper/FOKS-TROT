#pragma once

#include "global.h"

NTSTATUS PocInitCommPort();

VOID PocCloseCommPort();

#define POC_HELLO_KERNEL			1
#define POC_PRIVILEGE_DECRYPT		4
#define POC_PRIVILEGE_ENCRYPT		8
#define POC_ADD_PROCESS_RULES		9

typedef struct _POC_MESSAGE_HEADER
{
	int Command;
	int Length;

}POC_MESSAGE_HEADER, * PPOC_MESSAGE_HEADER;

typedef struct _POC_MESSAGE_PROCESS_RULES
{
	CHAR ProcessName[POC_MAX_NAME_LENGTH];
	ULONG Access;

}POC_MESSAGE_PROCESS_RULES, * PPOC_MESSAGE_PROCESS_RULES;