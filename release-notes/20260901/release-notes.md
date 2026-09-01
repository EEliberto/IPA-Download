感谢你使用 Pastel！20260901 版本带来了如下更新：

1.修复了部分 Mac 可能将设备 GUID 识别为 020000000000 的问题。设备 GUID 现改用 Asspp/ApplePackage 的 sysctl 接口方案读取，不再通过 ifconfig 获取。
2.新增设备 GUID 安全校验，自动淘汰 020000000000、000000000000、FFFFFFFFFFFF 等无效占位值；无法取得可靠设备标识时会阻止 Apple 账户登录，避免异常标识参与认证。
3.升级了设备会话版本并使旧会话自动失效。更新后 Apple 账户可能需要重新登录一次，以确保后续登录与下载请求使用正确且稳定的设备 GUID。
4.完善了 Swift 与 Node 两层防护，避免无效或变化后的设备 GUID 与旧 StoreServices 会话混用。

感谢 GitHub Issue #42 的用户反馈。由于 Apple 账户风控规则并不公开，目前无法确认异常设备 GUID 与账户锁定之间存在直接因果关系，但 Pastel 已按高风险问题处理并加入保护。

如果你有任何问题，请在 GitHub 中提交 Issue。谢谢！
