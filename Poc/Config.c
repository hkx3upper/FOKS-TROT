#include <fltKernel.h>

#define POC_MAX_NAME_LENGTH				320
#define MAX_SECURE_EXTENSION_COUNT		256
#define POC_EXTENSION_SIZE			    32

WCHAR secure_extension[MAX_SECURE_EXTENSION_COUNT][POC_EXTENSION_SIZE];
size_t secure_extension_count = 0;

WCHAR RelevantPath[256][POC_MAX_NAME_LENGTH] = { 0 };
ULONG current_relevant_path_inx = 0;

/*
* 在比较时，采用的是大小写无关的比较方式
* 这里添加你需要进行透明加密的文件的拓展名
*/
PWCHAR allowed_extension[MAX_SECURE_EXTENSION_COUNT] = {
		L"docx",
		L"doc",
		L"xlsx",
		L"xls",
		L"pptx",
		L"ppt",
		L"txt",
		L"png",
		L"jpg",
		L"mp4",
		L"dwg",
		L"iso",
		NULL };

/*
* 当且仅当文件位于以下文件夹下时才会进行透明加密
*/
const PWCHAR allowed_path[] = {
	L"C:\\Users\\wangzhankun\\Desktop\\testdata",
	L"C:\\Users\\hkx3upper\\Desktop",
	L"C:\\Desktop",
	NULL };

/*
* 只有授权进程才能正常加密解密文件
*/
const PWCHAR secure_process[] = {
	/*
	* PocUserPanel必须是授权进程，默认安装路径
	* 
	* explorer必须是授权进程，否则复制粘贴文件会失败
	*/
	L"C:\\Program Files\\hkx3upper\\PocUserPanel.exe",
	L"C:\\Windows\\explorer.exe",
	
	/*
	* 用户程序
	*/
	L"C:\\Windows\\System32\\notepad.exe",
	L"C:\\Desktop\\npp.7.8.1.bin\\notepad++.exe",

	L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11365\\office6\\wps.exe",
	L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11365\\office6\\wpp.exe",
	L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11365\\office6\\et.exe",
	L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11744\\office6\\wps.exe",
	L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11744\\office6\\wpp.exe",
	L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11744\\office6\\et.exe",
	L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11805\\office6\\wps.exe",
	L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11805\\office6\\wpp.exe",
	L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11805\\office6\\et.exe",

	L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.exe",
	L"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.exe",
	L"C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.exe",

	L"C:\\Program Files\\Microsoft VS Code\\Code.exe",
	L"C:\\Program Files\\Autodesk\\AutoCAD 2020\\acad.exe",
	L"C:\\WINDOWS\\system32\\certutil.exe",
	L"C:\\Program Files\\VideoLAN\\VLC\\vlc.exe",
	NULL };
