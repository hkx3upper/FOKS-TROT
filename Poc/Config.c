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
* 进程分为三类，授权进程，非授权进程和备份进程，
* 所有进程默认为非授权进程，非授权进程读密文（正常文件长度），不允许修改密文，
* 授权进程就是各种正常的办公软件，读写明文（正常文件长度），
* 备份进程主要是比如资源管理器将文件从机密文件夹中移出，但不能解密文件，
* 而且需要将整个带有文件标识尾的密文移出，它读密文（全部文件长度），允许修改密文。
* 
* 按照缓冲分类，授权进程是明文缓冲，非授权进程和备份进程是密文缓冲。
*/

/*
* 只有授权进程才能正常加密解密文件
*/
const PWCHAR secure_process[] = {
	/*
	* PocUserPanel必须是授权进程，默认安装路径
	*/
	L"C:\\Program Files\\hkx3upper\\PocUserPanel.exe",
	
	/*
	* 用户程序
	*/
	L"C:\\Windows\\System32\\notepad.exe",
	L"C:\\Desktop\\npp.7.8.1.bin\\notepad++.exe",
	L"C:\\Desktop\\Test.exe",

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


/*
* 备份进程可以读到完整的密文文件
*/
const PWCHAR backup_process[] = {

	L"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
	L"C:\\Windows\\explorer.exe",
	L"C:\\Windows\\System32\\dllhost.exe",

	NULL };
