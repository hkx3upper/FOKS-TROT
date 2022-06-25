
#include "global.h"
#include "fileobject.h"
#include "filefuncs.h"
#include "utils.h"


NTSTATUS PocInitShadowSectionObjectPointers(
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	IN OUT PPOC_STREAM_CONTEXT StreamContext)
/*
* 为ShadowSectionObjectPointer分配的内存要远大于sizeof(SectionObjectPointer)，
* 因为ntfs驱动有时会用(SectionObjectPointer+40)这种方式去取内存，
* 本来它指向的是Scb->NonpagedScb->SegmentObject后面的某个结构体，
* 但我们的ShadowSectionObjectPointer是独立出来的内存，所以要分配一个PAGE_SIZE大小的内存，这样肯定够用
*/
{

	if (NULL == StreamContext)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitShadowSectionObjectPointers->StreamContext is NULL.\n"));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	LARGE_INTEGER ByteOffset = { 0 };
	CHAR Buffer = { 0 };

	PFILE_OBJECT FileObject = FltObjects->FileObject;


	if (NULL == StreamContext->ShadowSectionObjectPointers)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitShadowSectionObjectPointers->ShadowSectionObjectPointers is NULL\n"));
		Status = STATUS_INVALID_PARAMETER;
		goto EXIT;
	}

	ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

	StreamContext->OriginSectionObjectPointers = FileObject->SectionObjectPointer;
	StreamContext->ShadowFileObject = FileObject;

	ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);

	FileObject->SectionObjectPointer = StreamContext->ShadowSectionObjectPointers;

	Status = FltReadFileEx(FltObjects->Instance, FileObject, &ByteOffset, 
		sizeof(Buffer), &Buffer, 0, NULL, NULL, NULL, NULL, NULL);

	if (!NT_SUCCESS(Status) && STATUS_END_OF_FILE != Status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitShadowSectionObjectPointers->FltReadFileEx init ciphertext cache failed. Status = 0x%x\n", Status));
		goto EXIT;
	}

	if (!CcIsFileCached(FileObject))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocInitShadowSectionObjectPointers->after FltReadFileEx file doesn't have cache.\n"));
		Status = STATUS_UNSUCCESSFUL;
		goto EXIT;
	}


	Status = STATUS_SUCCESS;

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
		("PocInitShadowSectionObjectPointers->Init %ws ciphertext cache map success.\nAllocationSize = %I64d ValidDataLength = %I64d FileSize = %I64d\n", 
			StreamContext->FileName,
			((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->AllocationSize.QuadPart,
			((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->ValidDataLength.QuadPart,
			((PFSRTL_ADVANCED_FCB_HEADER)(FileObject->FsContext))->FileSize.QuadPart));

EXIT:

	return Status;
}


NTSTATUS PocCleanupSectionObjectPointers(
	IN PPOC_STREAM_CONTEXT StreamContext)
/*
* 加解密minifilter想要支持热插拔还是比较难的，因为如果在Unload过程中仍有相关的IRP正在途中
* Unload时还没进到Pre的是无法处理的，而那些在Pre返回WITH_CALLBACK的还能处理
* 无法处理的这些IRP会导致数据的损坏，所以这里不释放正在使用的密文缓冲
* 因为即使用IoBuildSynchronousFsdRequest之类的函数发送IRP进行Cache的Purge
* 无法在Write中阻止密文的下发
* 同样，如果是明文缓冲会无法加密，导致明文泄露
*/
{
	if (NULL == StreamContext->FileName)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->StreamContext->FileName is NULL.\n", __FUNCTION__));
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (NULL != StreamContext->ShadowSectionObjectPointers)
	{

		if (NULL != StreamContext->ShadowSectionObjectPointers->DataSectionObject)
		{
			PocPurgeCache(
				StreamContext->FileName, 
				StreamContext->Instance, 
				StreamContext->ShadowSectionObjectPointers);
		}
		

		if (NULL == StreamContext->ShadowSectionObjectPointers->DataSectionObject &&
			NULL == StreamContext->ShadowSectionObjectPointers->SharedCacheMap)
		{
			ExEnterCriticalRegionAndAcquireResourceExclusive(StreamContext->Resource);

			if (NULL != StreamContext->ShadowSectionObjectPointers)
			{
				ExFreePoolWithTag(StreamContext->ShadowSectionObjectPointers, POC_STREAM_CONTEXT_TAG);
				StreamContext->ShadowSectionObjectPointers = NULL;

				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->%ws ExFreePoolWithTag1 ShadowSectionObjectPointers success.\n",
					__FUNCTION__,
					StreamContext->FileName));
			}

			ExReleaseResourceAndLeaveCriticalRegion(StreamContext->Resource);
			
			
			Status = STATUS_SUCCESS;
		}
		else
		{


			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Memory leak. CacheMap isn't NULL. Means file still has chipertext cache map.\n", __FUNCTION__));
			//KeBugCheck(POC_KEBUGCHECK_TAG);
		}
	}


	/*
	* 明文缓冲会无法加密，导致明文泄露，造成文件损坏，
	* 不过这里要是SetInformation重命名的话，不会有问题
	*/
	if (StreamContext->OriginSectionObjectPointers != NULL)
	{
		if (NULL != StreamContext->OriginSectionObjectPointers->DataSectionObject ||
			NULL != StreamContext->OriginSectionObjectPointers->SharedCacheMap)
		{
			PocPurgeCache(
				StreamContext->FileName,
				StreamContext->Instance,
				StreamContext->OriginSectionObjectPointers);

			if(NULL != StreamContext->OriginSectionObjectPointers->DataSectionObject)
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%s->Fatal error. CacheMap isn't NULL. Means file still has plaintext cache map.\n", __FUNCTION__));
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
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("PocChangeSectionObjectPointerSafe->SectionObjectPointers is NULL.\n"));
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
