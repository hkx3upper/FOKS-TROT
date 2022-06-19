#pragma once

#include <fltKernel.h>

#define READ_BUFFER_TAG					'rbtg'
#define WRITE_BUFFER_TAG				'wbtg'
#define FILE_NAME_BUFFER_TAG			'fnbt'
#define SHARE_ACCESS_TAG				'sast'
#define DOS_NAME_BUFFER_TAG				'dnbt'
#define POC_PR_LIST_TAG					'prBt'
#define POC_KAPC_BUFFER_TAG				'apCt'
#define POC_DPC_BUFFER_TAG              'dPBt'
#define POC_MESSAGE_TAG                 'mEtg'
#define POC_CREATE_BUFFER_TAG           'Cbtg'

#define POC_KEBUGCHECK_TAG              'mofo'      //Unknown bugcheck code (6d6f666f)

#define POC_TARGET_FILE_EXTENSION		0xFFFF7777
#define POC_STATUS_AES_INIT_FAILED		0xFFFF7776

#define POC_FILE_HAS_ENCRYPTION_TAILER	0xFFFF7774
#define POC_TO_APPEND_ENCRYPTION_TAILER	0xFFFF7773
#define POC_BEING_APPEND_ENC_TAILER		0xFFFF7772
#define POC_IS_BSOD_PROCESS		        0xFFFF7771
#define POC_IS_WORD_BACK_UP_FILE		0xFFFF7770
#define POC_TAILER_WRONG_FILE_NAME		0xFFFF776F
#define POC_IS_TARGET_FILE_EXTENSION	0xFFFF776E
#define POC_IRRELEVENT_FILE_EXTENSION	0xFFFF776D
#define POC_IS_UNAUTHORIZED_PROCESS		0xFFFF776C
#define POC_IS_AUTHORIZED_PROCESS		0xFFFF776B
#define POC_IS_IRRELEVENT_PATH			0xFFFF776A
#define POC_FILE_IS_PLAINTEXT			0xFFFF7769
#define POC_FILE_IS_CIPHERTEXT			0xFFFF7768
#define POC_BEING_DIRECT_ENCRYPTING		0xFFFF7767
#define POC_RENAME_TO_ENCRYPT			0xFFFF7766
#define POC_PROCESS_INTEGRITY_DAMAGE    0xFFFF7765
#define POC_IS_BACKUP_PROCESS           0xFFFF7764
#define POC_TO_DECRYPT_FILE             0xFFFF7763
#define POC_BEING_DECRYPT_FILE          0xFFFF7762

#define POC_OBJECT_NOT_FOUND		    0xFFFF7764
#define POC_OBJECT_REPEAT			    0xFFFF7763


#define POC_MAX_NAME_LENGTH				320
#define POC_EXTENSION_SIZE			    32


#define POC_ENCRYPTION_HEADER_FLAG		"FOKS-TROT"
#define POC_ENCRYPTION_HEADER_EA_TYPE	"AES-128 ECB"

extern PFLT_FILTER gFilterHandle;
extern PDEVICE_OBJECT gDeviceObject;


#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002


const static ULONG gTraceFlags = 0x00000001;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))


#define POC_POCUSER_PATH                L"C:\\Desktop\\PocUser.exe"

#define POC_CSRSS_PATH                  L"C:\\Windows\\System32\\csrss.exe"
#define POC_SVCHOST_PATH                L"C:\\Windows\\System32\\svchost.exe"
#define POC_EXPLORER_PATH               L"C:\\Windows\\explorer.exe"
#define POC_WMIPRVSE_PATH               L"C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"
#define POC_TASKMGR_PATH                L"C:\\Windows\\System32\\Taskmgr.exe"
#define POC_LSASS_PATH                  L"C:\\Windows\\System32\\lsass.exe"


#define POC_NOTEPAD_PATH                L"C:\\Windows\\System32\\notepad.exe"
#define POC_VSCODE_PATH                 L"C:\\Program Files\\Microsoft VS Code\\Code.exe"
#define POC_NOTEPADPLUS_PATH            L"C:\\Desktop\\npp.7.8.1.bin\\notepad++.exe"

#define POC_WPS_PATH                    L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11365\\office6\\wps.exe"
#define POC_WPP_PATH                    L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11365\\office6\\wpp.exe"
#define POC_ET_PATH                     L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11365\\office6\\et.exe"

#define POC_IS_PARAMETER_NULL(_ptr)                                                                                                 \
    {                                                                                                                               \
        if (_ptr == NULL)                                                                                                           \
        {                                                                                                                           \
            PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("%->POC_IS_PARAMETER_NULL: %s\n", __FUNCTION__, #_ptr)); \
            return STATUS_INVALID_PARAMETER;                                                                                        \
        }                                                                                                                           \
    }


#define MAX_SECURE_EXTENSION_COUNT              256
#define POC_MAX_AUTHORIZED_PROCESS_COUNT        32

extern WCHAR secure_extension[MAX_SECURE_EXTENSION_COUNT][POC_EXTENSION_SIZE];
extern size_t secure_extension_count;
extern PWCHAR allowed_extension[MAX_SECURE_EXTENSION_COUNT];
extern PWCHAR allowed_path[];
extern PWCHAR secure_process[];
extern PWCHAR backup_process[];
extern WCHAR RelevantPath[256][POC_MAX_NAME_LENGTH];
extern ULONG current_relevant_path_inx;
