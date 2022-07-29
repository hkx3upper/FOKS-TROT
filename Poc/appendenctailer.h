#pragma once


#include "global.h"
#include "context.h"
#include "filefuncs.h"
#include "cipher.h"

NTSTATUS PocInitAndStartAppendEncTailerThread();
NTSTATUS PocStopAndCleanAppendEncTailerThread();

NTSTATUS PocAppendEncTailerLazy(PPOC_STREAM_CONTEXT StreamContext);

