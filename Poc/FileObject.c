
#include "global.h"
#include "fileobject.h"
#include "filefuncs.h"


NTSTATUS PocInitShadowSectionObjectPointers(
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	IN OUT PPOC_STREAM_CONTEXT StreamContext)
{

	if (NULL == StreamContext)
	{
		PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,("PocInitShadowSectionObjectPointers->StreamContext is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	LARGE_INTEGER ByteOffset = { 0 };
	CHAR Buffer = { 0 };

	PFILE_OBJECT FileObject = FltObjects->FileObject;


	if (NULL == StreamContext->ShadowSectionObjectPointers)
	{
		PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,("PocInitShadowSectionObjectPointers->ShadowSectionObjectPointers is NULL\n"));
		Status = STATUS_INVALID_PARAMETER;
		goto EXIT;
	}

	ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

	StreamContext->OriginSectionObjectPointers = FileObject->SectionObjectPointer;

	ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

	FileObject->SectionObjectPointer = StreamContext->ShadowSectionObjectPointers;

	Status = FltReadFileEx(FltObjects->Instance, FileObject, &ByteOffset, 
		sizeof(Buffer), &Buffer, 0, NULL, NULL, NULL, NULL, NULL);

	if (!NT_SUCCESS(Status) && STATUS_END_OF_FILE != Status)
	{
		PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,("PocInitShadowSectionObjectPointers->FltReadFileEx init ciphertext cache failed. Status = 0x%x\n", Status));
		goto EXIT;
	}

	if (!CcIsFileCached(FileObject))
	{
		PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,("PocInitShadowSectionObjectPointers->after FltReadFileEx file doesn't have cache.\n"));
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}


	Status = STATUS_SUCCESS;
	PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,("PocInitShadowSectionObjectPointers->Init %ws ciphertext cache map success.\n", StreamContext->FileName));

EXIT:

	return Status;
}


NTSTATUS PocCleanupShadowSectionObjectPointers(
	IN PSECTION_OBJECT_POINTERS SectionObjectPointers)
{

	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	if (NULL != SectionObjectPointers)
	{
		if (NULL == SectionObjectPointers->SharedCacheMap)
		{
			ExFreePoolWithTag(SectionObjectPointers, POC_STREAM_CONTEXT_TAG);
			SectionObjectPointers = NULL;
			Status = STATUS_SUCCESS;
		}
		else
		{
			PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,("PocCleanupShadowSectionObjectPointers->SharedCacheMap isn't NULL. Means file still has cache map.\n"));
		}
	}


	return Status;
}


NTSTATUS PocChangeSectionObjectPointerSafe(
	IN OUT PFILE_OBJECT FileObject,
	IN PSECTION_OBJECT_POINTERS SectionObjectPointers)
{

	
	if (NULL == SectionObjectPointers)
	{
		PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,("PocChangeSectionObjectPointerSafe->SectionObjectPointers is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = STATUS_SUCCESS;

	PFSRTL_ADVANCED_FCB_HEADER AdvancedFcbHeader = NULL;

	AdvancedFcbHeader = FileObject->FsContext;

	ExEnterCriticalRegionAndAcquireResourceExclusive(AdvancedFcbHeader->PagingIoResource);

	FileObject->SectionObjectPointer = SectionObjectPointers;

	ExReleaseResourceAndLeaveCriticalRegion(AdvancedFcbHeader->PagingIoResource);


	return Status;
}
