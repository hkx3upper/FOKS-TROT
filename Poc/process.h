#pragma once

#include "global.h"

typedef struct _POC_PROCESS_RULES
{
	LIST_ENTRY ListEntry;
	PWCHAR ProcessName;
	ULONG Access;

	LIST_ENTRY PocCreatedProcessListHead;
	KSPIN_LOCK PocCreatedProcessListSpinLock;

}POC_PROCESS_RULES, * PPOC_PROCESS_RULES;

typedef struct _POC_CREATED_PROCESS_INFO
{
	LIST_ENTRY ListEntry;
	HANDLE ProcessId;
	BOOLEAN ThreadStartUp;

	PPOC_PROCESS_RULES OwnedProcessRule;

}POC_CREATED_PROCESS_INFO, * PPOC_CREATED_PROCESS_INFO;

extern LIST_ENTRY PocProcessRulesListHead;

#define POC_PR_ACCESS_READWRITE			1
#define POC_PR_ACCESS_BACKUP			2

#define PROCESS_QUERY_INFORMATION (0x0400)

NTSTATUS PocGetProcessName(
	IN PFLT_CALLBACK_DATA Data,
	IN OUT PWCHAR ProcessName);

NTSTATUS PocProcessRulesListInit();

VOID PocProcessRulesListCleanup();

NTSTATUS PocFindProcessRulesNodeByName(
	IN PWCHAR ProcessName,
	OUT PPOC_PROCESS_RULES* OutProcessRules,
	IN BOOLEAN Remove);

NTSTATUS PocFindProcessInfoNodeByPid(
	IN HANDLE ProcessId,
	IN PPOC_PROCESS_RULES ProcessRules,
	OUT PPOC_CREATED_PROCESS_INFO* OutProcessInfo,
	IN BOOLEAN Remove);

NTSTATUS PocFindProcessInfoNodeByPidEx(
	IN HANDLE ProcessId,
	OUT PPOC_CREATED_PROCESS_INFO* OutProcessInfo,
	IN BOOLEAN Remove,
	IN BOOLEAN IntegrityCheck);

NTSTATUS PocCreateProcessRulesNode(
	OUT PPOC_PROCESS_RULES* OutProcessRules);

NTSTATUS PocCreateProcessInfoNode(
	IN PPOC_PROCESS_RULES ProcessRules,
	OUT PPOC_CREATED_PROCESS_INFO* OutProcessInfo);

NTSTATUS PocIsUnauthorizedProcess(IN PWCHAR ProcessName);

NTSTATUS PocGetProcessType(IN PFLT_CALLBACK_DATA Data);
