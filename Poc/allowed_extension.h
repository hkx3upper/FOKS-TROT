#pragma once
#include <fltKernel.h>

#define MAX_SECURE_EXTENSION_COUNT  256

WCHAR secure_extension[MAX_SECURE_EXTENSION_COUNT][32];
size_t secure_extension_count = 0;

// 在比较时，采用的是大小写无关的比较方式
// 这里添加你需要进行透明加密的文件的拓展名
PWCHAR allowed_extension[MAX_SECURE_EXTENSION_COUNT] = {
	    L"docx",
	//    L"doc",
	//    L"xlsx",
	//    L"xls",
	//    L"pptx",
	//    L"ppt",
	L"txt",
	//    L"PNG",
	//    L"JPG",
	L"mp4",
	L"dwg",
	NULL};

// 当且仅当文件位于以下文件夹下时才会进行透明加密
const PWCHAR allowed_path[] = {
	L"C:\\Users\\wangzhankun\\Desktop\\testdata",
	L"C:\\Desktop",
	NULL};
