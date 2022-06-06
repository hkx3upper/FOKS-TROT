#pragma once

#include "global.h"
#include "import.h"


/**
 * @brief 获取要读取的文件的路径和拓展名
 * @param FileExtension 保存返回的拓展名。调用者需要事先分配内存空间
 * @param FileName 保存返回的Dos格式的文件路径。调用者需要事先分配内存空间。
*/
NTSTATUS PocGetFileNameOrExtension(
	IN PFLT_CALLBACK_DATA Data, 
	IN OUT PWCHAR FileExtension, 
	IN OUT PWCHAR FileName);

LONGLONG PocQueryEndOfFileInfo(
	IN PFLT_INSTANCE Instance, 
	IN PFILE_OBJECT FileObject);

NTSTATUS PocSetEndOfFileInfo(
	IN PFLT_INSTANCE Instance, 
	IN PFILE_OBJECT FileObject, 
	IN LONGLONG FileSize);

USHORT PocQueryVolumeSectorSize(IN PFLT_VOLUME Volume);

/**
 * @brief 该函数用于查找或者添加一个新的机密文件夹路径。
 * 如果是查找模式，那么folder_name可以是机密文件夹的路径，也可以是子文件或者子文件夹的路径。
 * @param [in] folder_name 文件夹路径。该路径可以是任意格式的路径，会在内部转为DOS格式。
 * @param [in] find_relevant_path 用于指示是查找还是添加。如果为true则为查询，否则为添加。需要保证传入的是Dos格式的路径。
 */
NTSTATUS PocAddOrFindRelevantPath(
	IN CONST PWCHAR folder_name, 
	BOOLEAN find_relevant_path);

NTSTATUS PocParseFileNameExtension(
	IN PWCHAR FileName, 
	IN OUT PWCHAR FileExtension);

NTSTATUS PocGetVolumeInstance(
	IN PFLT_FILTER pFilter,
	IN PUNICODE_STRING pVolumeName,
	OUT PFLT_INSTANCE* Instance);

/**
 * @brief 把文件的\\??\\C的路径转换为\\device\\harddiskvolume1的DOS格式的路径
 * @param [in] SymbolicLinkName 要转换的路径，不能为空
 * @param [out] LinkTarget 转换后的DOS格式的路径，转换后的路径会把'/'全部替换成'\\'，LinkTarget->Buffer会在函数内部分配内存，需要调用者自己释放。
 * UNICODE_STRING的结构体本身的内存空间需要调用者分配。
*/
NTSTATUS PocQuerySymbolicLink(
	IN PUNICODE_STRING SymbolicLinkName,
	OUT PUNICODE_STRING LinkTarget);

/**
 * @brief 把文件的符号链接转为DOS格式的路径。
 * 这里是将诸如C:\\Windows\\System32\\notepad.exe这样的路径转为\\??\\C:\\Windows\\System32\\notepad.exe之后，
 * 再调用PocQuerySymbolicLink函数，获取到DOS格式的路径。
 * 最终的路径格式类似于\\device\\harddiskvolume1\\windows\\system32\\notepad.exe
 * @param [in] FileName 文件的符号链接，不能为NULL
 * @param [out] DosPath 保存转换后的DOS格式的路径，不能为NULL,转换后的路径会把'/'全部替换成'\\'
*/
NTSTATUS PocSymbolLinkPathToDosPath(
	IN PWCHAR Path,
	IN OUT PWCHAR DosPath);

NTSTATUS PocAnsi2Unicode(
	const char* ansi, 
	wchar_t* unicode, 
	int unicode_size);

/**
 * @brief 添加一个新的需要进行透明加密的文件的拓展名
*/
NTSTATUS PocAddSecureExtension(IN const PCHAR extension);

NTSTATUS PocAddSecureExtensionW(IN CONST PWCHAR extension);

NTSTATUS PocBypassIrrelevantBy_PathAndExtension(IN PFLT_CALLBACK_DATA Data);

/**
 * @brief 自动识别任意格式的路径，并将其转化为DOS格式的路径
 * @param [in] src_path 要转化的路径，不能为NULL
 * @param [out] dest_path dos格式的路径，并保证将所有的'/'转为'\\'，不能为NULL
 * @param [in] max_len dest_path的最大长度，以字节为单位
 */
NTSTATUS PocAnyPath2DosPath(
	const PWCHAR src_path, 
	PWCHAR dest_path, 
	const size_t max_len_dest_path);

NTSTATUS PocBypassIrrelevantFileExtension(
	IN PWCHAR FileExtension);
