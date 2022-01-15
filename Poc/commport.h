#pragma once

#include "global.h"

NTSTATUS PocInitCommPort();

VOID PocCloseCommPort();

#define POC_HELLO_KERNEL			1
#define POC_PRIVILEGE_DECRYPT		4
#define POC_PRIVILEGE_ENCRYPT		8

typedef struct _POC_MESSAGE_HEADER
{
	int Command;
	int Length;

}POC_MESSAGE_HEADER, * PPOC_MESSAGE_HEADER;
