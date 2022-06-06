
#include "dpc.h"

KDEFERRED_ROUTINE PocKdeferredRoutine;

VOID PocSafePostCallbackShell(
	IN PDEVICE_OBJECT DeviceObject,
	IN PVOID Context);


VOID PocInitDpcRoutine()
{
	
	InitializeListHead(&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead);
	KeInitializeSpinLock(&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemSpinLock);

	KeInitializeTimer(&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->Timer);

	KeInitializeDpc(
		&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->Dpc,
		PocKdeferredRoutine,
		NULL);


	((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->IoWorkItem = IoAllocateWorkItem(gDeviceObject);

	if (NULL == ((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->IoWorkItem)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->IoAllocateWorkItem IoWorkItem failed.\n", __FUNCTION__));
		return;
	}
}


VOID PocKdeferredRoutine(
	IN KDPC* Dpc,
	IN PVOID DeferredContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	/*
	* Do not call IoQueueWorkItem or IoQueueWorkItemEx to queue a work item that is already in the queue.
	* Doing so can cause corruption of system data structures.
	* If your driver queues the same work item each time a particular driver routine runs,
	* you can use the following technique to avoid queuing the work item a second time if it is already in the queue:

	* The driver maintains a list of tasks for the worker routine.
	* This task list is available in the context that is supplied to the worker routine.
	* The worker routine and any driver routines that modify the task list synchronize their access to the list.
	* Each time the worker routine runs, it performs all the tasks in the list,
	* and removes each task from the list as the task is completed.
	* When a new task arrives, the driver adds this task to the list.
	* The driver queues the work item only if the task list was previously empty.
	*
	* The system worker thread removes the work item from the queue before it calls the worker thread.
	* Thus, a driver thread can safely queue the work item again as soon as the worker thread starts to run.
	*
	* 但我们把IoQueueWorkItem放在了Dpc中，而Dpc的Timer函数KeSetTimer设置时，如果此时还有Timer没到时，
	* 那它会取消之前的Timer，重新设置Timer。这样，IoQueueWorkItem也就不会有冲突了。
	*/

	IoQueueWorkItem(
		((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->IoWorkItem,
		PocSafePostCallbackShell,
		DelayedWorkQueue,
		NULL);

	//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->IoQueueWorkItem PocSafePostCallbackShell.\n", __FUNCTION__));

}


VOID PocSafePostCallbackShell(
	IN PDEVICE_OBJECT DeviceObject,
	IN PVOID Context)
{

	UNREFERENCED_PARAMETER(Context);

	PPOC_WORKITEM_LIST WorkItem = NULL;

	PLIST_ENTRY pListEntry = ((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead.Flink;
	KIRQL OldIrql = 0;

	while (pListEntry != &((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead)
	{

		WorkItem = CONTAINING_RECORD(pListEntry, POC_WORKITEM_LIST, ListEntry);



		if (NULL != WorkItem->WorkItemParam)
		{
			((PocSafePostCallback)(WorkItem->WorkItemParam->WorkerRoutine))(
				DeviceObject,
				WorkItem->WorkItemParam->Context);

			if (NULL != WorkItem->WorkItemParam->Event)
				KeSetEvent(WorkItem->WorkItemParam->Event, IO_NO_INCREMENT, TRUE);
		}
		


		OldIrql = KeAcquireSpinLockRaiseToDpc(&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemSpinLock);

		RemoveEntryList(&WorkItem->ListEntry);

		KeReleaseSpinLock(&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemSpinLock, OldIrql);

		if (NULL != WorkItem && NULL != WorkItem->WorkItemParam)
		{
			ExFreePoolWithTag(WorkItem->WorkItemParam, POC_DPC_BUFFER_TAG);
			WorkItem->WorkItemParam = NULL;
		}

		if (NULL != WorkItem)
		{
			ExFreePoolWithTag(WorkItem, POC_DPC_BUFFER_TAG);
			WorkItem = NULL;
		}

		pListEntry = pListEntry->Flink;
	}

}


NTSTATUS PocDoCompletionProcessingWhenSafe(
	IN PVOID SafePostCallback,
	IN PVOID Context,
	IN PKEVENT Event)
/*---------------------------------------------------------
函数名称:	PocDoCompletionProcessingWhenSafe
函数描述:	用于在高IRQL时安全调用SafePostCallback，如果是APC_LEVEL及一下，SafePostCallback函数会直接被调用
参数:		SafePostCallback是需要执行的函数，
			Context是SafePostCallback的参数，如果是局部变量，必须设置Event为无信号，然后KeWaitForSingleObject等待，
			Event是同步事件（可选），Event需要是分配在NonPagedPool的内存
			如果需要同步的话，使用KeInitializeEvent设置为NotificationEvent，初始状态无信号，
			SafePostCallback函数执行完后，Event会有信号。
作者:		hkx3upper
时间：		2022.06.05
更新维护:
---------------------------------------------------------*/
{

	if (NULL == SafePostCallback)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->SafePostCallback is NULL.\n", __FUNCTION__));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = STATUS_SUCCESS;

	PPOC_WORKITEM_LIST WorkItem = NULL;
	BOOLEAN ListEmpty = FALSE;

	LARGE_INTEGER DueTime = { 0 };


	if (KeGetCurrentIrql() <= APC_LEVEL)
	{
		((PocSafePostCallback)SafePostCallback)(gDeviceObject, Context);
		goto EXIT;

	}
	else if (KeGetCurrentIrql() == DISPATCH_LEVEL)
	{

	}
	else
	{
		KeBugCheck(IRQL_NOT_LESS_OR_EQUAL);
	}



	WorkItem = ExAllocatePoolWithTag(NonPagedPool, sizeof(POC_WORKITEM_LIST), POC_DPC_BUFFER_TAG);

	if (NULL == WorkItem)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag WorkItem failed.\n", __FUNCTION__));
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto EXIT;
	}

	RtlZeroMemory(WorkItem, sizeof(POC_WORKITEM_LIST));


	WorkItem->WorkItemParam = ExAllocatePoolWithTag(NonPagedPool, sizeof(POC_WORKITEM_PARAMETER), POC_DPC_BUFFER_TAG);

	if (NULL == WorkItem->WorkItemParam)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->ExAllocatePoolWithTag WorkItem->WorkItemParam failed.\n", __FUNCTION__));
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto EXIT;
	}

	RtlZeroMemory(WorkItem->WorkItemParam, sizeof(POC_WORKITEM_PARAMETER));


	WorkItem->WorkItemParam->WorkerRoutine = SafePostCallback;
	WorkItem->WorkItemParam->Context = Context;

	if(NULL != Event)
		WorkItem->WorkItemParam->Event = Event;

	if (IsListEmpty(&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead))
	{
		ListEmpty = TRUE;
	}


	ExInterlockedInsertTailList(
		&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead,
		&WorkItem->ListEntry,
		&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemSpinLock);


	/*
	* If the timer object was already in the timer queue,
	* it is implicitly canceled before being set to the new expiration time.
	* A call to KeSetTimer before the previously specified DueTime has expired cancels both the timerand the call to the Dpc,
	* if any, associated with the previous call.
	*/

	if (ListEmpty)
	{

#pragma warning(push)
#pragma warning(disable:4996)
		DueTime = RtlConvertLongToLargeInteger(-1);
#pragma warning(pop)

		if (KeSetTimer(
			&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->Timer,
			DueTime,
			&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->Dpc))
		{
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->The timer object was already in the system timer queue.\n", __FUNCTION__));
			Status = STATUS_SUCCESS;
			goto EXIT;
		}

		KeWaitForSingleObject(
			&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->Timer,
			Executive,
			KernelMode,
			FALSE,
			NULL);

		//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Timer expire.\n", __FUNCTION__));
	}


EXIT:

	return Status;
}


VOID PocWorkItemListCleanup()
{
	PPOC_WORKITEM_LIST WorkItem = NULL;
	PLIST_ENTRY pListEntry = { 0 };

	while (!IsListEmpty(&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead))
	{

		pListEntry = ExInterlockedRemoveHeadList(
			&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemListHead,
			&((PPOC_DEVICE_EXTENSION)(gDeviceObject->DeviceExtension))->WorkItemSpinLock);


		WorkItem = CONTAINING_RECORD(pListEntry, POC_WORKITEM_LIST, ListEntry);


		if (NULL != WorkItem && NULL != WorkItem->WorkItemParam)
		{
			ExFreePoolWithTag(WorkItem->WorkItemParam, POC_DPC_BUFFER_TAG);
			WorkItem->WorkItemParam = NULL;
		}

		if (NULL != WorkItem)
		{
			ExFreePoolWithTag(WorkItem, POC_DPC_BUFFER_TAG);
			WorkItem = NULL;
		}
	}
}
