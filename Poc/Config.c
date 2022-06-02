#include <fltKernel.h>

#define MAX_SECURE_EXTENSION_COUNT  256

WCHAR secure_extension[MAX_SECURE_EXTENSION_COUNT][32];
size_t secure_extension_count = 0;

// 在比较时，采用的是大小写无关的比较方式
// 这里添加你需要进行透明加密的文件的拓展名
PWCHAR allowed_extension[MAX_SECURE_EXTENSION_COUNT] = {
		L"docx",
		L"doc",
		L"xlsx",
		L"xls",
		L"pptx",
		L"ppt",
		L"txt",
		/*L"PNG",
		L"JPG",*/
		L"mp4",
		L"dwg",
		NULL };

// 当且仅当文件位于以下文件夹下时才会进行透明加密
const PWCHAR allowed_path[] = {
	L"C:\\Users\\wangzhankun\\Desktop\\testdata",
	L"C:\\Desktop",
	NULL };

const PWCHAR secure_process[] = {
	//系统服务
	// PocUser.exe必须是授权进程，explorer.exe对于.doc文件是必须的
	L"C:\\Windows\\explorer.exe",

	//用户程序
	L"C:\\Desktop\\PocUser.exe",
	L"C:\\Windows\\System32\\notepad.exe",
	L"C:\\Desktop\\npp.7.8.1.bin\\notepad++.exe",
	L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11365\\office6\\wps.exe",
	L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11365\\office6\\wpp.exe",
	L"C:\\Users\\hkx3upper\\AppData\\Local\\Kingsoft\\WPS Office\\11.1.0.11365\\office6\\et.exe",

	L"C:\\Program Files\\Microsoft VS Code\\Code.exe",
	L"C:\\Program Files\\Autodesk\\AutoCAD 2020\\acad.exe",
	L"C:\\WINDOWS\\system32\\certutil.exe",
	L"C:\\Program Files\\VideoLAN\\VLC\\vlc.exe",
	NULL };
