#pragma once
#include <fltKernel.h>
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
    NULL};
