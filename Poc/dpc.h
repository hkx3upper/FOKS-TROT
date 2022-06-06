#pragma once

#include "global.h"

typedef struct _POC_WORKITEM_PARAMETER
{
	PVOID WorkerRoutine;
	PVOID Context;

	PKEVENT Event;

}POC_WORKITEM_PARAMETER, * PPOC_WORKITEM_PARAMETER;


typedef struct _POC_WORKITEM_LIST
{
	LIST_ENTRY ListEntry;
	PPOC_WORKITEM_PARAMETER WorkItemParam;

}POC_WORKITEM_LIST, * PPOC_WORKITEM_LIST;


typedef struct _POC_DEVICE_EXTENSION
{
	KTIMER Timer;
	KDPC Dpc;

	PIO_WORKITEM IoWorkItem;

	LIST_ENTRY WorkItemListHead;
	KSPIN_LOCK WorkItemSpinLock;

}POC_DEVICE_EXTENSION, * PPOC_DEVICE_EXTENSION;


typedef VOID(*PocSafePostCallback) (
	IN PDEVICE_OBJECT,
	IN PVOID
	);

VOID PocInitDpcRoutine();

VOID PocWorkItemListCleanup();

NTSTATUS PocDoCompletionProcessingWhenSafe(
	IN PVOID SafePostCallback,
	IN PVOID Context,
	IN PKEVENT Event);
