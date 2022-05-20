# FOKS-TROT

## 基于Minifilter框架的双缓冲透明加解密驱动  

## 引言：  
本项目是个实验性项目，且作者对于文件系统等的理解难免会存在偏差，因此可能会产生误导，望读者辩证的学习，并且请读者遵循相关的开源协议。  
因为之前写过一个minifilter的透明加密解密驱动，但当时水平确实有限，有很多的问题，没有找到原因，只是进行了规避，导致在错误的基础上又产生了错误，所以在之前项目开发经验的基础上，写了这个项目。  
这个项目也打算作为毕设，如有雷同，纯属雷同s(-__-)b  

## 简介：  
本项目是一个使用minifilter框架的透明加密解密过滤驱动，当进程有写入特定的文件扩展名（比如txt，docx）文件的倾向时自动加密。授权进程想要读取密文文件时自动解密，非授权进程不解密，显示密文，且不允许修改密文，这里的加密或解密只针对NonCachedIo。桌面端也可以发送特权加密和特权解密命令，实现单独加密或解密。  
1.本项目使用双缓冲，授权进程和非授权进程分别使用明文缓冲和密文缓冲；  
2.使用StreamContext存放驱动运行时的文件信息，使用文件标识尾的方式，在文件的尾部4KB储存文件的解密信息；  
3.使用AES-128 ECB模式，16个字节以内扩展文件大小，大于16个字节，使用密文挪用（Ciphertext stealing）的方法，避免明文必须分块对齐(padding)的问题；  
4.Write和Read使用SwapBuffers的方式进行透明加密解密；  
5.特权加密和特权解密使用重入（Reentry）的方式，使驱动加密解密文件；  
6.解决FileRenameInformationEx和FileRenameInformation问题，因此可以自动加密解密docx，doc，pptx，ppt，xlsx，xls等使用tmp文件重命名方式读写的文件；  
7.注册进程相关回调，使用链表统一管理授权与非授权进程；注册进程与线程对象回调，保护进程EPROCESS,ETHREAD对象；对授权进程的代码段进行完整性校验。  

**It's a minifilter used for transparent-encrypting.**  
1.Double cache map (ciphertext cache and plaintext cache) by using two SectionObjectPointer.  
2.Using StreamContext and 4KB-tail to save information of encrypted file.  
3.Using AES-128 ECB Ciphertext-stealing to avoid extending file size when PagingIo.  
4.Read and Write using swapbuffers method in Windows-driver-samples-master.  
5.Direct-encrypt and direct-decrypt by reentry minifilter.  
6.Office .tmp file by FileRenameInformation and FileRenameInformationEx to encrypt.  
7.Registering process notify and object callback to manage and protect process. Then Checking authorized process .text intergity.  

## 编译及使用方法：  
1.安装CNG库：  
https://www.microsoft.com/en-us/download/details.aspx?id=30688  
需要在微软官网下载Cryptographic Provider Development Kit,  
项目->属性的VC++目录的包含目录，库目录设置相应的位置  
链接器的常规->附加库目录C:\Windows Kits\10\Cryptographic Provider Development Kit\Lib\x64  
输入->附加依赖项一定要设置为ksecdd.lib  
2.在`allowed_extensions.h`中设置机密文件扩展名，在`allowed_extensions.h`设置机密文件夹,
`secure_process.h`中设置机密进程  
3.使用Visual Studio 2019编译Debug x64驱动，编译User、UserDll和UserPanel  
4.建议在Windows 10 x64，NTFS环境运行(这里主要是FltFlushBuffers2的IRP_MN_FLUSH_AND_PURGE只支持NTFS)，

## 贡献者：  
hkx3upper: https://github.com/hkx3upper  
wangzhankun: https://github.com/wangzhankun

**欢迎愿意开发与测试项目的相关人员加入** 附代码规范  

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

### 代码规范  
#### 命名风格：  
1.使用大驼峰法命名函数和变量，尽量不使用_下划线命名  
2.使用全大写命名结构体和枚举，单词之间用下划线_间隔，以POC_为开头  
3.不要修改已有的变量名  
#### 注释风格：
```    
/*  
* 注释  
*/  
```  
#### 全局变量：  
以g开头，例如gFilterHandle  
#### 文件名：  
驱动中.c文件以大写字母开头，.h文件全小写字母  
#### PT_DBG_PRINT格式：  
%s->函数 变量 = %x.\n ，__FUNCTION__, 变量  
例如：  
```  
PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, 
	("%s->PocCreateProcessRulesNode failed. Status = 0x%x.\n", 
	__FUNCTION__, 
	Status));
```  
使用PT_DBG_PRINT，而不是DbgPrint，便于统一管理输出  
#### 函数间隔：  
函数在.h中声明时以一行回车做间隔，在.c文件中以两行回车做间隔  
#### 函数作者声明：  
之后增加或修改的函数应在函数前加一段声明：  
```  
/*---------------------------------------------------------
函数名称:   
函数描述:   
作者:
更新维护:  时间+维护者+修复的bug或添加的新功能
---------------------------------------------------------*/
```  

### 项目规范  
1.为了区别代码的作者，尽量不要重构已有的代码，不要将已有的代码重新封装，或拆解  
除非是实现其他的功能，有些重复的地方可以单独封装  
2.尽可能保持之前的**代码**和**目录结构**不变，除非是新添加功能或修复bug  