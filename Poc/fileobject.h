#pragma once

#include <fltKernel.h>
#include "context.h"

NTSTATUS PocInitShadowSectionObjectPointers(
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	IN OUT PPOC_STREAM_CONTEXT StreamContext);

NTSTATUS PocChangeSectionObjectPointerSafe(
	IN OUT PFILE_OBJECT FileObject,
	IN PSECTION_OBJECT_POINTERS SectionObjectPointers);

NTSTATUS PocCleanupSectionObjectPointers(
	IN PPOC_STREAM_CONTEXT StreamContext);