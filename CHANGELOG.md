## ChangeLog：
### 1.0.0.2265.01 2022.06.12
#### Changed：
- 删除PocUser项目，整合到PocUserPanel中
- 用InstallShield打包成安装包
#### Fixed：
- 修复重启后无法解密文件的问题（清除掉原始的缓冲）
- 修复特权加密16个字节以内文件失败的问题
- 重写Write对于CachedIo，16个字节以内文件的处理方式
- 删除StreamContext中的ProcessInfo成员，使用ProcessId替代
- 修改ppt，xls文件的处理方式，原来是重命名时加密，增加为：如果该文件未加密，那么打开时有写倾向以后自动加密
  
### 1.0.0.2265.02 2022.06.14
#### Added：
- 修复Shadow SectionObjectPointers的一个bug，将为它分配的内存大小增加为PAGE_SIZE，原因见PocInitShadowSectionObjectPointers_
- 增加备份权限的进程，比如VMTools和explorer.exe，它们可以将含有标识尾的完整密文文件移出虚拟机或机密文件夹
- 机密文件夹以外的文件移入机密文件夹，未加密的会自动加密，已加密过的重复加密后解密一次
- 允许加密或解密机密文件夹之外的文件
#### Fixed：
- 缩短文件写入以后到Close写入标识尾的时间
- 驱动卸载时清除掉原始的明文缓冲，防止明文泄露