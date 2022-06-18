#pragma once

#include "global.h"
#include "context.h"

typedef struct _POC_SWAP_BUFFER_CONTEXT
{
    PCHAR NewBuffer;
    PMDL NewMdl;
    PPOC_STREAM_CONTEXT StreamContext;
    ULONG OriginalLength;

    CHAR FileName[POC_MAX_NAME_LENGTH];

    BOOLEAN IsCacheExtend;

}POC_SWAP_BUFFER_CONTEXT, * PPOC_SWAP_BUFFER_CONTEXT;


FLT_PREOP_CALLBACK_STATUS
PocPreWriteOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
PocPostWriteOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);
