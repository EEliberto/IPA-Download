# Pastel (迄今空前强大的一款 IPA 下载工具)。
一款用于安装 IPA 历史版本的工具，适用于获取旧版应用并自动捕获数据包。下载后，可直接通过 AirDrop 传输至 iPhone、iPad 上并安装并使用。

目前只支持 macOS 26+ 且配备 Apple 芯片的 Mac。由于作者暂无 Windows PC 设备，故暂时没有 Windows 版本开发计划。

使用 SwiftUI 编译，完美适配 macOS 26 的 Liquid Glass 效果。

# 如果你觉得使用 Pastel 感到开心，可以请我喝杯咖啡 ☕️。
<img width="454" height="322" alt="image" src="https://github.com/user-attachments/assets/8b773cd2-2d4e-42b8-bcf4-d2bcf08e593c" />

# 主页面。
你可以轻松使用 Pastel 在对应地区的 App Store 内查看并搜索 App。更强大的是，它能直接根据你选择的 Apple 账户地区自动选择商店。在切换地区时，还会自动切换到你已登陆并对应地区的 Apple 账户。甚至支持直接下载一款此 Apple 账户从未下载过的 App。

<img width="1214" height="881" alt="image" src="https://github.com/user-attachments/assets/690166e2-78ad-42f8-9db2-40b79e435b71" />
<img width="956" height="656" alt="image" src="https://github.com/user-attachments/assets/f3685fee-445f-41bc-8fea-2d1e602dec92" />

# 现支持简体中文、繁体中文、日语、韩语和泰语作为主要语言。

<img width="1032" height="732" alt="image" src="https://github.com/user-attachments/assets/e6ef07a0-8834-457d-87f7-0bea14b45633" />

# 空前强大的下载页面。
你可以直接在下载页面找到已下载的 IPA 文件，并直接预览它的 App Icon，这针对一些特定节假日，比如 618 期间打广告的 App 格外实用。点击分享按钮，便可直接 AirDrop 到你的 iPhone 或 iPad 进行安装。

<img width="1138" height="805" alt="image" src="https://github.com/user-attachments/assets/1de14592-ebc6-4ee7-9b0c-17e7e0073171" />

# 初次使用。
初次使用，请前往“设置”>“Apple 账户”，添加你的 Apple 账户，一切数据都保存在 iCloud KeyChain，放心且安全。在登陆后完成双重认证，Pastel 会自动识别 Apple 账户的所属地区并完成登陆。解决了市面上已有 IPA 下载工具的很多问题，例如双重认证无法触发，经常丢失保存数据等 (使用了 GSA 技术来触发双重认证，更稳定且安全)。

<img width="556" height="301" alt="image" src="https://github.com/user-attachments/assets/c9efab09-2c9e-4593-908a-f01845b88465" />

# 众多来源可选。
云集了 Timbrd、Agsy、Bilin 下载源的版本 ID 信息，方便你快速找到对应的版本 ID。

如果你想要从 Apple 获取，也没问题，只需要点击 Apple，它就会从你的 Apple 账户获取一次此 App 的版本 ID 并显示 (如果未曾拥有此 App，则会自动完成获取，付费 App 除外)。

如果你知道对应 App 的版本 ID，也可手动输入版本 ID 下载。

<img width="460" height="90" alt="image" src="https://github.com/user-attachments/assets/4de67361-8727-4705-8718-f9be81bc7b01" />

# 鸣谢。
本项目参考了来自 ipatools 的部份代码和原理 https://github.com/beer-psi/ipatool.ts。

登陆流程依赖 SideStore 的 GSA。

多语言翻译依赖 Claude。

# 源码构建
首次克隆后，请先安装 Node 依赖：

```bash
cd NodeProject
npm install
```

然后使用 Xcode 打开 `Pastel.xcodeproj` 构建运行。
