#pragma once

#include "global.h"
#include "process.h"


typedef struct _POC_PAGE_TEMP_BUFFER
{
    LONGLONG StartingVbo;
    LONGLONG ByteCount;
    PCHAR Buffer;

}POC_PAGE_TEMP_BUFFER, * PPOC_PAGE_TEMP_BUFFER;


//
//  Stream context data structure
//

typedef struct _POC_STREAM_CONTEXT 
{

    ULONG Flag;
    PWCHAR FileName;

    /*
    * FileSize中存着明文==密文大小，因为写进去的尾是NonCachedIo，所以有扇区对齐，不是紧接着密文写的
    * FileSize主要是用于隐藏尾部，在PostQueryInformation和PreRead，PostRead中使用
    * FileSize会在PostWrite中更新，并在PostClose中写进尾部，以便驱动启动后第一次打开文件时，从尾部中取出
    */
    LONGLONG FileSize;

    PSECTION_OBJECT_POINTERS OriginSectionObjectPointers;
    PSECTION_OBJECT_POINTERS ShadowSectionObjectPointers;

    BOOLEAN IsCipherText;

    // 将倒数第二个扇区大小的块存在StreamContext->PageNextToLastForWrite中
    POC_PAGE_TEMP_BUFFER PageNextToLastForWrite;

    // 等待操作的进程结束以后，写入文件标识尾用
    PPOC_CREATED_PROCESS_INFO ProcessInfo[POC_MAX_AUTHORIZED_PROCESS_COUNT];
    HANDLE ProcessId[POC_MAX_AUTHORIZED_PROCESS_COUNT];
    BOOLEAN AppendTailerThreadStart;
    PFLT_VOLUME Volume;
    PFLT_INSTANCE Instance;

    PERESOURCE Resource;

} POC_STREAM_CONTEXT, * PPOC_STREAM_CONTEXT;

#define POC_STREAM_CONTEXT_SIZE         sizeof(POC_STREAM_CONTEXT)
#define POC_RESOURCE_TAG                      'cRxC'
#define POC_STREAM_CONTEXT_TAG                'cSxC'

typedef struct _POC_VOLUME_CONTEXT 
{

    //
    //  Holds the sector size for this volume.
    //

    ULONG SectorSize;

} POC_VOLUME_CONTEXT, * PPOC_VOLUME_CONTEXT;

#define MIN_SECTOR_SIZE 0x200
#define POC_VOLUME_CONTEXT_SIZE                 sizeof(POC_VOLUME_CONTEXT)
#define POC_VOLUME_CONTEXT_TAG                  'cVxC'


NTSTATUS PocCreateStreamContext(
    _In_ PFLT_FILTER FilterHandle, 
    _Outptr_ PPOC_STREAM_CONTEXT* StreamContext);

NTSTATUS
PocFindOrCreateStreamContext(
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN CreateIfNotFound,
    OUT PPOC_STREAM_CONTEXT* StreamContext,
    OUT PBOOLEAN ContextCreated);

VOID PocContextCleanup(
    _In_ PFLT_CONTEXT Context, 
    _In_ FLT_CONTEXT_TYPE ContextType);

NTSTATUS PocUpdateNameInStreamContext(
    IN PPOC_STREAM_CONTEXT StreamContext,
    IN PWCHAR NewFileName);

VOID PocUpdateFlagInStreamContext(
    IN PPOC_STREAM_CONTEXT StreamContext,
    IN ULONG Flag);

NTSTATUS PocUpdateStreamContextProcessInfo(
    IN PFLT_CALLBACK_DATA Data,
    IN OUT PPOC_STREAM_CONTEXT StreamContext);

VOID PocInstanceSetupWhenSafe(
    IN PDEVICE_OBJECT DeviceObject,
    IN PVOID Context);;
