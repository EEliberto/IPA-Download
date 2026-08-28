这是一个强制更新的版本，此前版本已不再受支持。

Pastel 即日起采用日期作为版本号。20260828 带来了如下更新和修复：

1.尝试修复了登陆错误，逻辑参考 ([https://github.com/maksimryabkin/ipatool-sapfix](https://github.com/maksimryabkin/ipatool-sapfix))。由于端口改变，如果输入 Apple 账户密码错误，则 App 已经无法判断到底是密码错误还是需要 2FA 双重认证密钥，因此请确保 Apple 账户密码正确。且由于依赖 macOS 自带的 StoreServices 服务，因此请确保 macOS 为真正的 Mac，而非虚拟机，否则依然无法登陆。

2.解决了旧版本 Session 残留的问题，新版本可能会需要重新登陆一次 Apple 账户。

3.修复部份 UI 错误，优化逻辑，解决了不少残留 bug。

如果有任何问题，请在 Github 提交 Issue，谢谢！
