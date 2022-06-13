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