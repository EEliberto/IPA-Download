import AppKit
import Combine
import CryptoKit
import ObjectiveC
import Security
import Sparkle
import SwiftUI

private let appDisplayName = "Pastel"

private func copyToPasteboard(_ string: String) {
    let value = string.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !value.isEmpty else { return }
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(value, forType: .string)
}

private extension Notification.Name {
    static let pastelSelectAllRows = Notification.Name("PastelSelectAllRows")
    static let pastelRefreshActivePanel = Notification.Name("PastelRefreshActivePanel")
}

private enum ApplicationKeyboardShortcutInterceptor {
    private static var didInstall = false

    static func install() {
        guard !didInstall else { return }
        guard
            let original = class_getInstanceMethod(NSApplication.self, #selector(NSApplication.sendEvent(_:))),
            let replacement = class_getInstanceMethod(NSApplication.self, #selector(NSApplication.pastel_sendEvent(_:)))
        else { return }

        method_exchangeImplementations(original, replacement)
        didInstall = true
        KeyboardCommandRouter.shared.installMenuItem()
    }
}

private final class KeyboardCommandRouter: NSObject, NSMenuItemValidation {
    static let shared = KeyboardCommandRouter()

    private override init() {}

    func installMenuItem() {
        DispatchQueue.main.async {
            self.patchSelectAllMenuItem()
        }
    }

    func handle(_ event: NSEvent) -> Bool {
        guard event.type == .keyDown else { return false }
        guard isCommandOnly(event, matching: "a") else { return false }

        if shouldPassThroughToTextEditor {
            return false
        }

        selectAllRows()
        return true
    }

    @objc func selectAll(_ sender: Any?) {
        if shouldPassThroughToTextEditor,
           let textView = NSApp.keyWindow?.firstResponder as? NSTextView {
            textView.selectAll(sender)
        } else {
            selectAllRows()
        }
    }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        true
    }

    private var shouldPassThroughToTextEditor: Bool {
        KeyboardShortcutState.shared.isTextEditing
            && NSApp.keyWindow?.firstResponder is NSTextView
    }

    private func selectAllRows() {
        NotificationCenter.default.post(name: .pastelSelectAllRows, object: nil)
    }

    private func isCommandOnly(_ event: NSEvent, matching character: String) -> Bool {
        let modifiers = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
        let ignoredModifiers: NSEvent.ModifierFlags = [.capsLock, .numericPad, .function]
        let extraModifiers = modifiers.subtracting([.command]).subtracting(ignoredModifiers)
        return modifiers.contains(.command)
            && extraModifiers.isEmpty
            && event.charactersIgnoringModifiers?.lowercased() == character
    }

    private func patchSelectAllMenuItem() {
        guard let mainMenu = NSApp.mainMenu else { return }
        if let item = selectAllMenuItem(in: mainMenu) {
            configureSelectAllMenuItem(item)
            return
        }

        guard let editMenu = editMenu(in: mainMenu) else { return }
        editMenu.addItem(.separator())
        let item = NSMenuItem(title: String(localized: "全选"),
                              action: #selector(selectAll(_:)),
                              keyEquivalent: "a")
        editMenu.addItem(item)
        configureSelectAllMenuItem(item)
    }

    private func configureSelectAllMenuItem(_ item: NSMenuItem) {
        item.target = self
        item.action = #selector(selectAll(_:))
        item.keyEquivalent = "a"
        item.keyEquivalentModifierMask = [.command]
        item.isEnabled = true
    }

    private func selectAllMenuItem(in menu: NSMenu) -> NSMenuItem? {
        for item in menu.items {
            if isSelectAllMenuItem(item) {
                return item
            }

            if let submenu = item.submenu,
               let found = selectAllMenuItem(in: submenu) {
                return found
            }
        }

        return nil
    }

    private func isSelectAllMenuItem(_ item: NSMenuItem) -> Bool {
        item.action == #selector(NSResponder.selectAll(_:))
            || (item.keyEquivalent.lowercased() == "a"
                && item.keyEquivalentModifierMask.intersection(.deviceIndependentFlagsMask).contains(.command))
    }

    private func editMenu(in mainMenu: NSMenu) -> NSMenu? {
        mainMenu.items.compactMap(\.submenu).first { menu in
            menu.items.contains { item in
                item.action == #selector(NSText.copy(_:))
                    || (item.keyEquivalent.lowercased() == "c"
                        && item.keyEquivalentModifierMask.intersection(.deviceIndependentFlagsMask).contains(.command))
            }
        }
    }
}

private extension NSApplication {
    @objc func pastel_sendEvent(_ event: NSEvent) {
        if KeyboardCommandRouter.shared.handle(event) {
            return
        }

        pastel_sendEvent(event)
    }
}

struct StoredCredentials: Codable {
    var selectedAccountID: UUID?
    var accounts: [StoredAccount]

    var normalized: StoredCredentials {
        let selectedID = selectedAccountID.flatMap { id in
            accounts.contains { $0.id == id } ? id : nil
        } ?? accounts.first?.id
        return StoredCredentials(selectedAccountID: selectedID, accounts: accounts)
    }
}

struct StoredAccount: Codable, Identifiable, Hashable {
    var id: UUID
    var label: String
    var countryCode: String
    var appleAccount: String
    var password: String

    var displayLabel: String {
        let cleanAppleAccount = appleAccount.trimmingCharacters(in: .whitespacesAndNewlines)
        return cleanAppleAccount.isEmpty ? String(localized: "未命名 Apple 账户") : cleanAppleAccount
    }

    var countryName: String {
        AppStoreCountry.named(countryCode).name
    }
}

private struct LegacyStoredCredentials: Codable {
    let appleAccount: String
    let password: String
}

enum CredentialVaultError: LocalizedError {
    case keychainOperationFailed(String, OSStatus)
    case invalidLegacyKeyData

    var errorDescription: String? {
        switch self {
        case .keychainOperationFailed(let operation, let status):
            return String(localized: "Keychain \(operation) 失败：\(Int(status))")
        case .invalidLegacyKeyData:
            return String(localized: "旧版凭据密钥无效")
        }
    }
}

private enum DeviceGUIDStore {
    private static let service = "com.allenmiao.ipahistorydownload.device-guid"
    private static let account = "DeviceIdentifier"
    private static let hexCharacterSet = CharacterSet(charactersIn: "0123456789abcdefABCDEF")

    static func current() -> String {
        if let saved = load(), !saved.isEmpty {
            return saved
        }
        let value = systemIdentifier() ?? randomIdentifier()
        try? save(value)
        return value
    }

    private static func load() -> String? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let data = result as? Data,
              let value = String(data: data, encoding: .utf8)
        else {
            return nil
        }
        return normalized(value)
    }

    private static func save(_ value: String) throws {
        guard let normalized = normalized(value) else { return }
        let data = Data(normalized.utf8)
        let update: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrDescription as String: "Pastel StoreServices Device GUID"
        ]

        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw CredentialVaultError.keychainOperationFailed("更新", updateStatus)
        }

        var addQuery = baseQuery
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrDescription as String] = "Pastel StoreServices Device GUID"
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw CredentialVaultError.keychainOperationFailed("写入", addStatus)
        }
    }

    private static var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    private static func normalized(_ value: String) -> String? {
        let scalars = value.unicodeScalars.filter { hexCharacterSet.contains($0) }
        let clean = String(String.UnicodeScalarView(scalars)).uppercased()
        guard clean.count >= 12 else { return nil }
        return String(clean.prefix(12))
    }

    private static func systemIdentifier() -> String? {
        for interface in ["en0", "en1"] {
            guard let text = ifconfig(interface),
                  let value = firstMatch(in: text, pattern: #"ether\s+([0-9a-fA-F:]{17})"#),
                  let guid = normalized(value)
            else {
                continue
            }
            return guid
        }
        return nil
    }

    private static func ifconfig(_ interface: String) -> String? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
        task.arguments = [interface]
        let output = Pipe()
        task.standardOutput = output
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
            guard task.terminationStatus == 0 else { return nil }
            let data = output.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8)
        } catch {
            return nil
        }
    }

    private static func firstMatch(in text: String, pattern: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        guard let match = regex.firstMatch(in: text, range: range),
              match.numberOfRanges > 1,
              let valueRange = Range(match.range(at: 1), in: text)
        else {
            return nil
        }
        return String(text[valueRange])
    }

    private static func randomIdentifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 6)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess {
            return UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(12).uppercased()
        }
        return bytes.map { String(format: "%02X", $0) }.joined()
    }
}

private struct StoredAccountMetadata: Codable {
    var id: UUID
    var label: String
    var countryCode: String
    var appleAccount: String
}

private struct StoredCredentialsMetadata: Codable {
    var selectedAccountID: UUID?
    var accounts: [StoredAccountMetadata]

    init(_ credentials: StoredCredentials) {
        selectedAccountID = credentials.selectedAccountID
        accounts = credentials.accounts.map {
            StoredAccountMetadata(id: $0.id,
                                  label: $0.label,
                                  countryCode: $0.countryCode,
                                  appleAccount: $0.appleAccount)
        }
    }
}

private enum KeychainPasswordStore {
    private static let service = "com.allenmiao.ipahistorydownload.apple-account-password"

    static func savePassword(_ password: String, for account: StoredAccount) throws {
        let passwordData = Data(password.utf8)
        let query = baseQuery(for: account.id)
        let update: [String: Any] = [
            kSecValueData as String: passwordData,
            kSecAttrLabel as String: account.displayLabel,
            kSecAttrDescription as String: "Pastel Apple account password"
        ]

        let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }

        guard updateStatus == errSecItemNotFound else {
            throw CredentialVaultError.keychainOperationFailed("更新", updateStatus)
        }

        var addQuery = query
        addQuery[kSecValueData as String] = passwordData
        addQuery[kSecAttrLabel as String] = account.displayLabel
        addQuery[kSecAttrDescription as String] = "Pastel Apple account password"
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw CredentialVaultError.keychainOperationFailed("写入", addStatus)
        }
    }

    static func loadPassword(for accountID: UUID) throws -> String {
        var query = baseQuery(for: accountID)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return ""
        }
        guard status == errSecSuccess else {
            throw CredentialVaultError.keychainOperationFailed("读取", status)
        }
        guard let data = result as? Data,
              let password = String(data: data, encoding: .utf8) else {
            return ""
        }
        return password
    }

    static func deletePassword(for accountID: UUID) throws {
        let status = SecItemDelete(baseQuery(for: accountID) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CredentialVaultError.keychainOperationFailed("删除", status)
        }
    }

    static func deleteAllPasswords() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CredentialVaultError.keychainOperationFailed("删除", status)
        }
    }

    private static func baseQuery(for accountID: UUID) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: accountID.uuidString
        ]
    }
}

enum CredentialVault {
    static func save(_ credentials: StoredCredentials) throws {
        try prepareDirectory()

        let normalized = credentials.normalized
        for account in normalized.accounts {
            if !account.password.isEmpty {
                try KeychainPasswordStore.savePassword(account.password, for: account)
            }
        }

        let metadata = StoredCredentialsMetadata(normalized)
        let payload = try JSONEncoder().encode(metadata)
        try payload.write(to: metadataURL, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: metadataURL.path)
        try? deleteLegacyEncryptedFiles()
    }

    static func load() throws -> StoredCredentials? {
        if FileManager.default.fileExists(atPath: metadataURL.path) {
            let data = try Data(contentsOf: metadataURL)
            let metadata = try JSONDecoder().decode(StoredCredentialsMetadata.self, from: data)
            let accounts = metadata.accounts.map { item in
                StoredAccount(id: item.id,
                              label: item.label,
                              countryCode: item.countryCode,
                              appleAccount: item.appleAccount,
                              password: "")
            }
            return StoredCredentials(selectedAccountID: metadata.selectedAccountID, accounts: accounts).normalized
        }

        guard let legacyCredentials = try loadLegacyEncryptedCredentials() else {
            return nil
        }

        try save(legacyCredentials)
        return legacyCredentials.normalized
    }

    static func deleteStoredCredentials() throws {
        if FileManager.default.fileExists(atPath: metadataURL.path) {
            try FileManager.default.removeItem(at: metadataURL)
        }
        try KeychainPasswordStore.deleteAllPasswords()
        try? deleteLegacyEncryptedFiles()
    }

    static func loadPassword(for accountID: UUID) throws -> String {
        try KeychainPasswordStore.loadPassword(for: accountID)
    }

    static func deletePassword(for accountID: UUID) throws {
        try KeychainPasswordStore.deletePassword(for: accountID)
    }

    private static var metadataURL: URL {
        applicationSupportURL.appendingPathComponent("accounts.json")
    }

    private static var credentialsURL: URL {
        applicationSupportURL.appendingPathComponent("credentials.enc")
    }

    private static var keyURL: URL {
        applicationSupportURL.appendingPathComponent("credential-key.bin")
    }

    private static var applicationSupportURL: URL {
        let baseURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return baseURL.appendingPathComponent(appDisplayName, isDirectory: true)
    }

    private static func prepareDirectory() throws {
        try FileManager.default.createDirectory(at: applicationSupportURL, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: applicationSupportURL.path)
    }

    private static func loadLegacyEncryptedCredentials() throws -> StoredCredentials? {
        guard FileManager.default.fileExists(atPath: credentialsURL.path) else {
            return nil
        }

        guard let keyData = try loadLegacyKeyData() else {
            return nil
        }
        let key = SymmetricKey(data: keyData)
        let encryptedData = try Data(contentsOf: credentialsURL)
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
        do {
            let payload = try AES.GCM.open(sealedBox, using: key)
            let decoder = JSONDecoder()
            if let credentials = try? decoder.decode(StoredCredentials.self, from: payload) {
                return credentials.normalized
            }

            if let legacyCredentials = try? decoder.decode(LegacyStoredCredentials.self, from: payload) {
                let account = StoredAccount(
                    id: UUID(),
                    label: String(localized: "默认账户"),
                    countryCode: "cn",
                    appleAccount: legacyCredentials.appleAccount,
                    password: legacyCredentials.password
                )
                return StoredCredentials(selectedAccountID: account.id, accounts: [account])
            }

            return nil
        } catch {
            return nil
        }
    }

    private static func deleteLegacyEncryptedFiles() throws {
        if FileManager.default.fileExists(atPath: credentialsURL.path) {
            try FileManager.default.removeItem(at: credentialsURL)
        }
        if FileManager.default.fileExists(atPath: keyURL.path) {
            try FileManager.default.removeItem(at: keyURL)
        }
    }

    private static func loadLegacyKeyData() throws -> Data? {
        guard FileManager.default.fileExists(atPath: keyURL.path) else {
            return nil
        }

        let data = try Data(contentsOf: keyURL)
        guard data.count == 32 else {
            throw CredentialVaultError.invalidLegacyKeyData
        }
        return data
    }
}

enum NodeRuntimeError: LocalizedError {
    case missingResourceDirectory
    case missingProject(URL)
    case missingNode(URL)
    case processFailed(String)

    var errorDescription: String? {
        switch self {
        case .missingResourceDirectory:
            return String(localized: "无法找到 App 资源目录。")
        case .missingProject(let url):
            return String(localized: "无法找到内置 Node 项目：\(url.path)")
        case .missingNode(let url):
            return String(localized: "内置 Node 缺失或不可执行：\(url.path)")
        case .processFailed(let message):
            return message.isEmpty ? String(localized: "Node 查询失败。") : message
        }
    }
}

struct NodeRuntime {
    static func locate() throws -> (projectURL: URL, mainURL: URL, nodeURL: URL) {
        guard let resourceURL = Bundle.main.resourceURL else {
            throw NodeRuntimeError.missingResourceDirectory
        }

        let projectURL = resourceURL.appendingPathComponent("NodeProject", isDirectory: true)
        let mainURL = projectURL.appendingPathComponent("main.js")
        guard FileManager.default.fileExists(atPath: mainURL.path) else {
            throw NodeRuntimeError.missingProject(mainURL)
        }

        let nodeURL = resourceURL.appendingPathComponent("node/bin/node")
        guard FileManager.default.isExecutableFile(atPath: nodeURL.path) else {
            throw NodeRuntimeError.missingNode(nodeURL)
        }

        return (projectURL, mainURL, nodeURL)
    }

    static func baseEnvironment() -> [String: String] {
        var environment = ProcessInfo.processInfo.environment
        environment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        environment["IPA_LANG"] = AppLanguage.effectiveCode
        return environment
    }

    static func runJSON(arguments: [String], timeout: TimeInterval = 30) async throws -> Data {
        try await Task.detached(priority: .userInitiated) {
            let runtime = try locate()
            let fileManager = FileManager.default
            let tempURL = fileManager.temporaryDirectory
                .appendingPathComponent("Pastel-\(UUID().uuidString)", isDirectory: true)
            try fileManager.createDirectory(at: tempURL, withIntermediateDirectories: true)
            defer { try? fileManager.removeItem(at: tempURL) }

            let outputURL = tempURL.appendingPathComponent("stdout.json")
            let errorURL = tempURL.appendingPathComponent("stderr.txt")
            fileManager.createFile(atPath: outputURL.path, contents: nil)
            fileManager.createFile(atPath: errorURL.path, contents: nil)

            let outputHandle = try FileHandle(forWritingTo: outputURL)
            let errorHandle = try FileHandle(forWritingTo: errorURL)
            defer {
                try? outputHandle.close()
                try? errorHandle.close()
            }

            let task = Process()
            task.executableURL = runtime.nodeURL
            task.arguments = arguments
            task.currentDirectoryURL = runtime.projectURL
            task.environment = baseEnvironment()
            task.standardOutput = outputHandle
            task.standardError = errorHandle

            try task.run()

            let deadline = Date().addingTimeInterval(timeout)
            while task.isRunning {
                if Date() >= deadline {
                    task.terminate()
                    throw NodeRuntimeError.processFailed(String(localized: "请求超时，请重试。"))
                }
                do {
                    try await Task.sleep(nanoseconds: 40_000_000)
                } catch {
                    task.terminate()
                    throw error
                }
            }

            try? outputHandle.close()
            try? errorHandle.close()

            let outputData = try Data(contentsOf: outputURL)
            let errorData = try Data(contentsOf: errorURL)
            if task.terminationStatus != 0 {
                let message = String(data: errorData, encoding: .utf8)
                    ?? String(data: outputData, encoding: .utf8)
                    ?? String(localized: "Node 查询失败。")
                throw NodeRuntimeError.processFailed(message.trimmingCharacters(in: .whitespacesAndNewlines))
            }

            return outputData
        }.value
    }
}

struct RunConfig {
    let appleAccount: String
    let password: String
    var code: String
    let appID: String
    let versionID: String
    let downloadDir: String
    var listVersionIDs: Bool = false
    var validateLogin: Bool = false
    var appIsFree: String = ""
    var appCountry: String = "us"
    var allowAppAcquisition: Bool = false
    var removeAppStoreUpdateMetadata: Bool = false
}

struct WindowChromeConfigurator: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async {
            configure(view.window)
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async {
            configure(nsView.window)
        }
    }

    private func configure(_ window: NSWindow?) {
        guard let window else { return }
        ApplicationKeyboardShortcutInterceptor.install()
        KeyboardCommandRouter.shared.installMenuItem()
        window.styleMask.insert(.fullSizeContentView)
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isMovableByWindowBackground = false
    }
}

struct SettingsWindowConfigurator: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async {
            configure(view.window)
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async {
            configure(nsView.window)
        }
    }

    private func configure(_ window: NSWindow?) {
        guard let window else { return }
        window.styleMask.insert(.fullSizeContentView)
        window.titlebarAppearsTransparent = false
        window.titleVisibility = .hidden
        window.toolbarStyle = .unified
    }
}

private struct IBeamCursorRect: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        IBeamCursorRectView()
    }

    func updateNSView(_ nsView: NSView, context: Context) {}
}

private final class IBeamCursorRectView: NSView {
    private var trackingArea: NSTrackingArea?

    override func hitTest(_ point: NSPoint) -> NSView? {
        nil
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        window?.invalidateCursorRects(for: self)
    }

    override func resetCursorRects() {
        super.resetCursorRects()
        addCursorRect(bounds, cursor: .iBeam)
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let trackingArea {
            removeTrackingArea(trackingArea)
        }
        let options: NSTrackingArea.Options = [
            .activeInKeyWindow,
            .mouseEnteredAndExited,
            .mouseMoved,
            .cursorUpdate,
            .inVisibleRect
        ]
        let area = NSTrackingArea(rect: .zero, options: options, owner: self, userInfo: nil)
        addTrackingArea(area)
        trackingArea = area
    }

    override func mouseEntered(with event: NSEvent) {
        NSCursor.iBeam.set()
    }

    override func mouseMoved(with event: NSEvent) {
        NSCursor.iBeam.set()
    }

    override func cursorUpdate(with event: NSEvent) {
        NSCursor.iBeam.set()
    }
}

func ipaIsVerificationChallenge(_ text: String) -> Bool {
    return text.contains("[2FA]")
}

func ipaProgressValue(from text: String) -> Double? {
    let normalized = text.replacingOccurrences(of: "\r", with: "\n")
    let lines = normalized.split(separator: "\n", omittingEmptySubsequences: false).map(String.init).reversed()
    for line in lines {
        guard line.contains("%"), line.contains("MB") else { continue }
        if let range = line.range(of: #"(\d+(?:\.\d+)?)\s*%"#, options: .regularExpression) {
            let token = line[range].replacingOccurrences(of: "%", with: "").trimmingCharacters(in: .whitespacesAndNewlines)
            if let value = Double(token) { return min(max(value / 100, 0), 1) }
        }
    }
    return nil
}

func downloadErrorMessage(from log: String) -> String {
    let lines = log
        .replacingOccurrences(of: "\r", with: "\n")
        .split(separator: "\n")
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty && !$0.hasPrefix("@@IPA:") }
    let text = lines.joined(separator: "\n")
    guard !text.isEmpty else {
        return String(localized: "下载未能完成。请稍后再试。")
    }

    if ipaIsVerificationChallenge(text) {
        return String(localized: "需要完成 Apple 账户双重认证。请输入验证码后继续。")
    }
    if text.localizedCaseInsensitiveContains("Your password has changed")
        || text.localizedCaseInsensitiveContains("password token is expired")
        || text.contains("本地会话可能已失效") {
        return String(localized: "Apple 账户会话已失效。请重新登录后再试。")
    }
    if text.contains("账号或密码不正确")
        || text.localizedCaseInsensitiveContains("wrong password")
        || text.localizedCaseInsensitiveContains("invalid password") {
        return String(localized: "Apple 账户或密码不正确。请检查后再试。")
    }
    if text.contains("验证码不正确") || text.localizedCaseInsensitiveContains("verification code") {
        return String(localized: "验证码不正确或已过期。请重新获取后再试。")
    }
    if text.contains("网络请求失败")
        || text.localizedCaseInsensitiveContains("network")
        || text.localizedCaseInsensitiveContains("timed out")
        || text.localizedCaseInsensitiveContains("unable to connect") {
        return String(localized: "无法连接 Apple 服务器。请检查网络连接后再试。")
    }
    if text.contains("服务器繁忙") || text.localizedCaseInsensitiveContains("server busy") {
        return String(localized: "Apple 服务器暂时不可用。请稍后再试。")
    }
    if text.contains("获取许可失败")
        || text.localizedCaseInsensitiveContains("license")
        || text.contains("付费应用未购买") {
        return String(localized: "此 Apple 账户暂时无法获取该 App。请确认账号已拥有此 App 后再试。")
    }
    if text.contains("文件签名失败")
        || text.contains("MD5 校验失败")
        || text.localizedCaseInsensitiveContains("invalid signature") {
        return String(localized: "IPA 文件处理失败。请重新下载后再试。")
    }

    if let detail = lines.reversed().compactMap({ cleanDownloadErrorDetail($0) }).first, !detail.isEmpty {
        return String(localized: "下载未能完成。") + "\n" + detail
    }
    return String(localized: "下载未能完成。请稍后再试。")
}

private func cleanDownloadErrorDetail(_ line: String) -> String? {
    var value = line
    if value.contains("任务结束") || value.contains("任务已开始") {
        return nil
    }
    if let range = value.range(of: #"信息:\s*"([^"]+)""#, options: .regularExpression) {
        value = String(value[range])
            .replacingOccurrences(of: #"信息:\s*""#, with: "", options: .regularExpression)
            .replacingOccurrences(of: #"""#, with: "")
    }
    value = value
        .replacingOccurrences(of: #"\s*\[(?:X|OK|!|2FA|[^\]]*失败[^\]]*|[^\]]*成功[^\]]*)\]\s*"#, with: " ", options: .regularExpression)
        .replacingOccurrences(of: #"^[^：:]{1,12}[：:]\s*"#, with: "", options: .regularExpression)
        .replacingOccurrences(of: #"\s{2,}"#, with: " ", options: .regularExpression)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    return value.isEmpty ? nil : value
}

enum JobStatus: Equatable {
    case running, done, failed

    var displayName: String {
        switch self {
        case .running: return String(localized: "运行中")
        case .done: return String(localized: "完成")
        case .failed: return String(localized: "失败")
        }
    }
}

struct AppLanguage: Identifiable, Hashable {
    let code: String
    var id: String { code }

    static let overrideKey = "appLanguageOverride"

    static let all: [AppLanguage] = [
        AppLanguage(code: ""),
        AppLanguage(code: "zh-Hans"),
        AppLanguage(code: "zh-Hant"),
        AppLanguage(code: "en"),
        AppLanguage(code: "ja"),
        AppLanguage(code: "ko"),
        AppLanguage(code: "th"),
    ]

    var displayName: String {
        if code.isEmpty { return String(localized: "跟随系统") }
        let loc = Locale(identifier: code)
        return loc.localizedString(forIdentifier: code) ?? code
    }

    static var effectiveCode: String {
        let override = UserDefaults.standard.string(forKey: overrideKey) ?? ""
        if !override.isEmpty { return override }
        return Bundle.main.preferredLocalizations.first ?? "zh-Hans"
    }
}

enum SettingsTab: String, CaseIterable, Identifiable {
    case account, storage, language, about
    var id: String { rawValue }

    var title: String {
        switch self {
        case .account: return String(localized: "Apple 账户")
        case .storage: return String(localized: "下载与存储")
        case .language: return String(localized: "语言与地区")
        case .about: return String(localized: "关于")
        }
    }

    var systemImage: String {
        switch self {
        case .account: return "person.crop.circle"
        case .storage: return "folder"
        case .language: return "globe"
        case .about: return "info.circle"
        }
    }

    var symbolColor: Color {
        switch self {
        case .account: return .blue
        case .storage: return .orange
        case .language: return .purple
        case .about: return .gray
        }
    }
}

private let credentialSaveQueue = DispatchQueue(label: "com.allenmiao.ipadownload.credentialsave", qos: .utility)

@MainActor
final class AccountStore: ObservableObject {
    @Published private(set) var accounts: [StoredAccount] = []
    @Published var selectedAccountID: UUID?
    @Published var statusMessage: String = ""

    @Published var isValidating = false
    @Published var validationMessage = ""
    @Published var needsCode = false
    @Published var saveTick = 0

    private var process: Process?
    private var pipes: (Pipe, Pipe)?
    private var validationLog = ""
    private var pending: (email: String, password: String, editingID: UUID?, country: String)?

    var selectedAccount: StoredAccount? { accounts.first { $0.id == selectedAccountID } }
    var hasSelectedLogin: Bool {
        guard let a = selectedAccount else { return false }
        return !a.appleAccount.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func password(for account: StoredAccount) throws -> String {
        guard let index = accounts.firstIndex(where: { $0.id == account.id }) else {
            return account.password
        }
        if !accounts[index].password.isEmpty {
            return accounts[index].password
        }

        let password = try CredentialVault.loadPassword(for: account.id)
        if !password.isEmpty {
            accounts[index].password = password
        }
        return password
    }

    func load() {
        do {
            if let creds = try CredentialVault.load() {
                accounts = creds.accounts
                selectedAccountID = creds.selectedAccountID ?? accounts.first?.id
                statusMessage = accounts.isEmpty ? "" : String(localized: "已载入 \(accounts.count) 个 Apple 账户")
            }
        } catch {
            statusMessage = error.localizedDescription
        }
    }

    func select(_ account: StoredAccount) {
        guard selectedAccountID != account.id else { return }
        selectedAccountID = account.id
        persist(String(localized: "已切换到 \(account.displayLabel)"))
    }

    func delete(_ account: StoredAccount) {
        let wasSelected = account.id == selectedAccountID
        try? CredentialVault.deletePassword(for: account.id)
        accounts.removeAll { $0.id == account.id }
        guard !accounts.isEmpty else {
            selectedAccountID = nil
            try? CredentialVault.deleteStoredCredentials()
            statusMessage = String(localized: "已删除 \(account.displayLabel)")
            return
        }
        if wasSelected { selectedAccountID = accounts.first?.id }
        persist(String(localized: "已删除 \(account.displayLabel)"))
    }

    private func persist(_ message: String) {
        statusMessage = message
        let snapshot = StoredCredentials(selectedAccountID: selectedAccountID, accounts: accounts)
        credentialSaveQueue.async {
            do {
                try CredentialVault.save(snapshot)
            } catch {
                let description = error.localizedDescription
                Task { @MainActor [weak self] in
                    self?.statusMessage = description
                }
            }
        }
    }

    private func normalizedAppleAccount(_ value: String) -> String {
        value
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive],
                     locale: Locale(identifier: "en_US_POSIX"))
    }

    private func containsAccount(_ appleAccount: String, excluding editingID: UUID?) -> Bool {
        let target = normalizedAppleAccount(appleAccount)
        guard !target.isEmpty else { return false }
        return accounts.contains { account in
            account.id != editingID && normalizedAppleAccount(account.appleAccount) == target
        }
    }

    func validate(email: String, password: String, editingID: UUID?, fallbackCountry: String) {
        let cleanEmail = email.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanEmail.isEmpty else { validationMessage = String(localized: "请输入 Apple 账户。"); return }
        guard !password.isEmpty else { validationMessage = String(localized: "请输入密码。"); return }
        guard !containsAccount(cleanEmail, excluding: editingID) else {
            needsCode = false
            validationMessage = String(localized: "此 Apple 账户已经存在。")
            return
        }
        pending = (cleanEmail, password, editingID, fallbackCountry)
        validationMessage = String(localized: "正在登录并验证 Apple 账户…")
        runValidation(code: "")
    }

    func submitCode(_ code: String) {
        let clean = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty, pending != nil else { return }
        needsCode = false
        validationMessage = String(localized: "正在完成 Apple 账户双重认证…")
        runValidation(code: clean)
    }

    func cancelValidation() {
        process?.terminate()
        cleanup()
        isValidating = false
        needsCode = false
        validationMessage = ""
        pending = nil
    }

    private func runValidation(code: String) {
        guard let pending else { return }
        let runtime: (projectURL: URL, mainURL: URL, nodeURL: URL)
        do { runtime = try NodeRuntime.locate() }
        catch { isValidating = false; validationMessage = error.localizedDescription; return }

        isValidating = true
        needsCode = false
        validationLog = ""

        let task = Process()
        task.executableURL = runtime.nodeURL
        task.arguments = ["main.js"]
        task.currentDirectoryURL = runtime.projectURL
        var env = NodeRuntime.baseEnvironment()
        env["APPLE_ID"] = pending.email
        env["APPLE_PWD"] = pending.password
        env["APPLE_CODE"] = code
        env["IPA_VALIDATE_LOGIN"] = "1"
        env["IPA_DEVICE_GUID"] = DeviceGUIDStore.current()
        if let sessionURL = Self.sessionDirectoryURL() { env["IPA_SESSION_DIR"] = sessionURL.path }
        task.environment = env

        let out = Pipe(); let err = Pipe()
        task.standardOutput = out; task.standardError = err
        pipes = (out, err)
        let handler: @Sendable (FileHandle) -> Void = { [weak self] h in
            let d = h.availableData
            guard !d.isEmpty else { return }
            let t = String(data: d, encoding: .utf8) ?? String(decoding: d, as: UTF8.self)
            Task { @MainActor in self?.validationLog += t.replacingOccurrences(of: "\r", with: "\n") }
        }
        out.fileHandleForReading.readabilityHandler = handler
        err.fileHandleForReading.readabilityHandler = handler
        task.terminationHandler = { [weak self] finished in
            let exit = finished.terminationStatus
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 120_000_000)
                self?.finishValidation(exitCode: exit)
            }
        }
        do { try task.run(); process = task }
        catch { cleanup(); isValidating = false; validationMessage = error.localizedDescription }
    }

    private func finishValidation(exitCode: Int32) {
        cleanup()
        let log = validationLog
        if exitCode == 0 {
            isValidating = false
            needsCode = false
            if saveValidated(from: log) {
                validationMessage = ""
                saveTick += 1
            }
        } else if ipaIsVerificationChallenge(log) {
            isValidating = false
            needsCode = true
            validationMessage = String(localized: "验证码已发送至你的受信任 Apple 设备，请输入双重认证验证码。")
        } else {
            isValidating = false
            needsCode = false
            validationMessage = validationError(from: log)
        }
    }

    private func saveValidated(from log: String) -> Bool {
        guard let pending else { return false }
        guard !containsAccount(pending.email, excluding: pending.editingID) else {
            validationMessage = String(localized: "此 Apple 账户已经存在。")
            self.pending = nil
            return false
        }
        var countryCode = pending.country
        if let line = log.split(separator: "\n").map(String.init).first(where: { $0.contains("\"storefront\"") }),
           let data = line.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let storefront = obj["storefront"] as? String,
           let mapped = storefrontCountryCode(storefront) {
            countryCode = mapped
        }
        let id = pending.editingID ?? UUID()
        let account = StoredAccount(id: id, label: "", countryCode: countryCode,
                                    appleAccount: pending.email, password: pending.password)
        if let idx = accounts.firstIndex(where: { $0.id == id }) {
            accounts[idx] = account
        } else {
            accounts.append(account)
        }
        if pending.editingID == nil || selectedAccountID == nil { selectedAccountID = id }
        self.pending = nil
        persist(String(localized: "已验证并保存 \(account.displayLabel)（\(AppStoreCountry.named(countryCode).name)）"))
        return true
    }

    private func validationError(from log: String) -> String {
        let lines = log.split(separator: "\n").map(String.init)
        if let x = lines.last(where: { $0.contains("[X]") }),
           let cleaned = cleanDownloadErrorDetail(x) {
            return cleaned
        }
        return String(localized: "无法登录，请确认你的 Apple 账户和密码是否正确。")
    }

    private func cleanup() {
        pipes?.0.fileHandleForReading.readabilityHandler = nil
        pipes?.1.fileHandleForReading.readabilityHandler = nil
        pipes = nil
        process = nil
    }

    private static func sessionDirectoryURL() -> URL? {
        let baseURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        let sessionURL = baseURL
            .appendingPathComponent(appDisplayName, isDirectory: true)
            .appendingPathComponent("sessions", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: sessionURL, withIntermediateDirectories: true)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: sessionURL.path)
            return sessionURL
        } catch { return nil }
    }
}

@MainActor
final class DownloadManager: ObservableObject {
    struct Job: Identifiable {
        let id: String
        var label: String
        var status: JobStatus = .running
        var log: String = ""
        var progress: Double? = 0
        var isPackaging: Bool = false
        var needsCode: Bool = false
        var awaitingSession: Bool = false
    }

    @Published private(set) var jobs: [String: Job] = [:]
    private var processes: [String: Process] = [:]
    private var pipes: [String: (Pipe, Pipe)] = [:]
    private var configs: [String: RunConfig] = [:]

    var anyRunning: Bool { !processes.isEmpty }
    var runningCount: Int { processes.count }
    func isRunning(_ id: String) -> Bool { processes[id] != nil }
    func job(_ id: String) -> Job? { jobs[id] }
    var firstJobNeedingCode: Job? { jobs.values.first { $0.needsCode } }
    var codeNeededJobID: String? { jobs.values.first { $0.needsCode }?.id }
    var focusJob: Job? {
        jobs.values.first { processes[$0.id] != nil } ?? jobs.values.first
    }

    func start(id: String, label: String, config: RunConfig) {
        guard processes[id] == nil else { return }
        configs[id] = config

        let runtime: (projectURL: URL, mainURL: URL, nodeURL: URL)
        do { runtime = try NodeRuntime.locate() }
        catch {
            jobs[id] = Job(id: id, label: label, status: .failed, log: error.localizedDescription + "\n", progress: nil)
            return
        }

        jobs[id] = Job(id: id, label: label, log: String(localized: "任务已开始。") + "\n")

        let task = Process()
        task.executableURL = runtime.nodeURL
        task.arguments = ["main.js"]
        task.currentDirectoryURL = runtime.projectURL
        var env = NodeRuntime.baseEnvironment()
        env["APPLE_ID"] = config.appleAccount
        env["APPLE_PWD"] = config.password
        env["APPLE_CODE"] = config.code
        env["DOWNLOAD_APPID"] = config.appID
        env["DOWNLOAD_VERSION_ID"] = config.versionID
        env["DOWNLOAD_DIR"] = config.downloadDir
        if config.listVersionIDs { env["IPA_LIST_VERSION_IDS"] = "1" }
        if config.validateLogin { env["IPA_VALIDATE_LOGIN"] = "1" }
        if config.allowAppAcquisition { env["IPA_ALLOW_APP_ACQUIRE"] = "1" }
        env["IPA_DEVICE_GUID"] = DeviceGUIDStore.current()
        if !config.appIsFree.isEmpty { env["IPA_APP_IS_FREE"] = config.appIsFree }
        env["IPA_APP_COUNTRY"] = config.appCountry
        if config.removeAppStoreUpdateMetadata { env["IPA_REMOVE_APP_STORE_UPDATE_METADATA"] = "1" }
        if let sessionURL = Self.sessionDirectoryURL() { env["IPA_SESSION_DIR"] = sessionURL.path }
        task.environment = env

        let stdout = Pipe(); let stderr = Pipe()
        task.standardOutput = stdout; task.standardError = stderr
        pipes[id] = (stdout, stderr)
        stdout.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            guard !d.isEmpty else { return }
            let t = String(data: d, encoding: .utf8) ?? String(decoding: d, as: UTF8.self)
            Task { @MainActor in self?.append(id: id, t) }
        }
        stderr.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            guard !d.isEmpty else { return }
            let t = String(data: d, encoding: .utf8) ?? String(decoding: d, as: UTF8.self)
            Task { @MainActor in self?.append(id: id, t) }
        }
        task.terminationHandler = { [weak self] finished in
            let code = finished.terminationStatus
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 120_000_000)
                self?.finish(id: id, exitCode: code)
            }
        }

        do { try task.run(); processes[id] = task }
        catch {
            cleanup(id: id)
            var j = jobs[id] ?? Job(id: id, label: label)
            j.status = .failed; j.progress = nil
            j.log += String(localized: "无法启动内置 Node：\(error.localizedDescription)") + "\n"
            jobs[id] = j
        }
    }

    func submitCode(id: String, code: String) {
        guard let cfg = configs[id] else { return }
        let label = jobs[id]?.label ?? ""
        for (otherID, otherJob) in jobs where otherID != id && otherJob.needsCode {
            var oj = otherJob; oj.needsCode = false; oj.awaitingSession = true; jobs[otherID] = oj
        }
        var j = jobs[id]; j?.needsCode = false; if let j { jobs[id] = j }
        var retryConfig = cfg; retryConfig.code = code
        start(id: id, label: label, config: retryConfig)
    }

    func stop(id: String) { processes[id]?.terminate() }
    func stopAll() { processes.values.forEach { $0.terminate() } }

    func remove(id: String) {
        guard processes[id] == nil else { return }
        jobs[id] = nil; configs[id] = nil
    }
    func clearFinished() {
        for (k, v) in jobs where processes[k] == nil && v.status == .done { jobs[k] = nil; configs[k] = nil }
    }

    private func append(id: String, _ text: String) {
        guard var job = jobs[id] else { return }
        let normalized = text.replacingOccurrences(of: "\r", with: "\n")
        if normalized.contains("@@IPA:phase=packaging") { job.isPackaging = true }
        let cleaned = normalized
            .split(separator: "\n", omittingEmptySubsequences: false)
            .filter { !$0.hasPrefix("@@IPA:") }
            .joined(separator: "\n")
        job.log += cleaned
        if let p = ipaProgressValue(from: job.log) { job.progress = p }
        jobs[id] = job
    }

    private func finish(id: String, exitCode: Int32) {
        cleanup(id: id)
        guard var job = jobs[id] else { return }
        job.progress = nil; job.isPackaging = false
        if exitCode == 0 {
            job.status = .done; job.needsCode = false; job.awaitingSession = false
            job.log += "\n" + String(localized: "任务完成。") + "\n"
            jobs[id] = job
            for (otherID, otherJob) in jobs where otherID != id && processes[otherID] == nil && otherJob.awaitingSession {
                if let cfg = configs[otherID] {
                    var retryConfig = cfg; retryConfig.code = ""
                    start(id: otherID, label: otherJob.label, config: retryConfig)
                }
            }
        } else {
            job.status = .failed
            job.needsCode = ipaIsVerificationChallenge(job.log)
            job.log += "\n" + String(localized: "任务结束，退出码：\(Int(exitCode))") + "\n"
            jobs[id] = job
        }
    }

    private func cleanup(id: String) {
        if let (o, e) = pipes[id] {
            o.fileHandleForReading.readabilityHandler = nil
            e.fileHandleForReading.readabilityHandler = nil
        }
        pipes[id] = nil
        processes[id] = nil
    }

    private static func sessionDirectoryURL() -> URL? {
        let baseURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        let sessionURL = baseURL
            .appendingPathComponent(appDisplayName, isDirectory: true)
            .appendingPathComponent("sessions", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: sessionURL, withIntermediateDirectories: true)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: sessionURL.path)
            return sessionURL
        } catch { return nil }
    }
}

struct AppSearchResult: Decodable, Identifiable, Hashable {
    let id: String
    let name: String
    let artistName: String
    let bundleId: String
    let version: String
    let minimumOsVersion: String
    let price: String
    let fileSizeBytes: String
    let artworkUrl: String
    let trackViewUrl: String
    let currentVersionReleaseDate: String
    let source: String
    let platform: String?

    var fileSizeText: String {
        formatByteString(fileSizeBytes)
    }

    var isVisionApp: Bool {
        let normalizedPlatform = (platform ?? "").lowercased()
        return normalizedPlatform.contains("vision")
            || artworkUrl.lowercased().contains(".lsr/")
            || trackViewUrl.lowercased().contains("/vision")
    }
}

struct SearchResponse: Decodable {
    let queryType: String
    let count: Int
    let offset: Int?
    let limit: Int?
    let hasMore: Bool?
    let results: [AppSearchResult]
}

struct VersionRecord: Decodable, Identifiable, Hashable {
    let id: String
    let version: String
    let versionId: String
    let date: String
    let size: String
    let source: String
}

struct VersionsResponse: Decodable {
    let appId: String
    let provider: String
    let count: Int
    let versions: [VersionRecord]
    let errors: [String]
}

struct DownloadedItem: Identifiable, Hashable {
    let id: String
    let fileURL: URL
    let appName: String
    let developer: String
    let bundleId: String
    let appId: String
    let groupKey: String
    let version: String
    let versionId: String
    let sizeBytes: Int64
    let appleAccount: String
    let storefrontId: String
    let downloadDate: Date
    let removesAppStoreUpdates: Bool
    let artworkUrl: String
    let softwarePlatform: String

    var sizeText: String {
        guard sizeBytes > 0 else { return "—" }
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter.string(fromByteCount: sizeBytes)
    }

    var dateText: String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.string(from: downloadDate)
    }

    var isVisionApp: Bool {
        softwarePlatform.lowercased().contains("vision")
            || artworkUrl.lowercased().contains(".lsr/")
    }
}

struct DownloadedAppGroup: Identifiable {
    let id: String
    let items: [DownloadedItem]
    var appName: String { items.first?.appName ?? "" }
    var developer: String { items.first?.developer ?? "" }
    var bundleId: String { items.first?.bundleId ?? "" }
    var appId: String { items.first?.appId ?? "" }
    var storefrontId: String { items.first?.storefrontId ?? "" }
    var iconPath: String { items.first?.id ?? "" }
    var artworkUrl: String { items.first?.artworkUrl ?? "" }
    var softwarePlatform: String { items.first?.softwarePlatform ?? "" }
    var isVisionApp: Bool { items.first?.isVisionApp ?? false }
}

private enum AppSearchPlatform: String, CaseIterable, Identifiable {
    case iphone
    case ipad
    case vision

    var id: String { rawValue }

    var symbolName: String {
        switch self {
        case .iphone: return "iphone"
        case .ipad: return "ipad"
        case .vision: return "vision.pro"
        }
    }

    var title: String {
        switch self {
        case .iphone: return "iPhone"
        case .ipad: return "iPad"
        case .vision: return "Vision"
        }
    }

    static func named(_ value: String) -> AppSearchPlatform {
        allCases.first { $0.rawValue == value } ?? .iphone
    }
}

private enum IPADownloadVariant: String {
    case original
    case noUpdates

    init(removeAppStoreUpdateMetadata: Bool) {
        self = removeAppStoreUpdateMetadata ? .noUpdates : .original
    }

    var removesAppStoreUpdates: Bool {
        self == .noUpdates
    }
}

private func downloadedFileKey(_ value: String, variant: IPADownloadVariant) -> String {
    "\(variant.rawValue)|\(value)"
}

func countryFlagEmoji(_ code: String) -> String {
    let base: UInt32 = 0x1F1E6
    var scalars = String.UnicodeScalarView()
    for u in code.uppercased().unicodeScalars where (65...90).contains(u.value) {
        if let scalar = Unicode.Scalar(base + (u.value - 65)) { scalars.append(scalar) }
    }
    let flag = String(scalars)
    return flag.isEmpty ? "🏳️" : flag
}

func appStoreRegion(_ storefrontId: String) -> (flag: String, name: String) {
    let id = storefrontId.split(separator: "-").first.map(String.init) ?? storefrontId
    guard let code = storefrontCountryCode(storefrontId) else {
        return ("🏳️", id.isEmpty ? String(localized: "未知地区") : String(localized: "地区 \(id)"))
    }
    let name = Locale.current.localizedString(forRegionCode: code.uppercased()) ?? code.uppercased()
    return (countryFlagEmoji(code), name)
}

func storefrontCountryCode(_ storefrontId: String) -> String? {
    let id = storefrontId.split(separator: "-").first.map(String.init) ?? storefrontId
    let map: [String: String] = [
        "143441": "us", "143465": "cn", "143463": "hk", "143470": "tw", "143462": "jp",
        "143466": "kr", "143464": "sg", "143444": "gb", "143443": "de", "143442": "fr",
        "143450": "it", "143454": "es", "143455": "ca", "143460": "au", "143461": "nz",
        "143452": "nl", "143458": "dk", "143456": "se", "143457": "no", "143459": "ch",
        "143467": "in", "143447": "fi", "143469": "ru", "143468": "mx", "143480": "br",
        "143445": "at", "143446": "be", "143448": "gr", "143449": "ie", "143451": "lu",
        "143453": "pt", "143475": "th", "143476": "id", "143477": "my", "143474": "vn",
        "143479": "ph", "143505": "tr", "143489": "pl", "143478": "za", "143482": "sa",
        "143481": "ae"
    ]
    return map[id]
}

struct AppStoreCountry: Identifiable, Hashable {
    let code: String

    var id: String { code }

    var name: String {
        let localized = Locale.current.localizedString(forRegionCode: code.uppercased()) ?? code.uppercased()
        if code == "cn" {
            switch localized {
            case "中国大陆": return "中国"
            case "中國大陸", "中國內地": return "中國"
            case "Mainland China": return "China"
            default: break
            }
        }
        return localized
    }

    static let all: [AppStoreCountry] = [
        "ae", "ag", "ai", "al", "am", "ao", "ar", "at", "au", "az", "bb", "bd",
        "be", "bf", "bg", "bh", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bw",
        "by", "bz", "ca", "cg", "ch", "ci", "cl", "cm", "cn", "co", "cr", "cv",
        "cy", "cz", "de", "dk", "dm", "do", "dz", "ec", "ee", "eg", "es", "fi",
        "fj", "fm", "fr", "gb", "gd", "gh", "gm", "gr", "gt", "gw", "gy", "hk",
        "hn", "hr", "hu", "id", "ie", "il", "in", "iq", "is", "it", "jm", "jo",
        "jp", "ke", "kg", "kh", "kn", "kr", "kw", "ky", "kz", "la", "lb", "lc",
        "lk", "lr", "lt", "lu", "lv", "ma", "md", "mg", "mk", "ml", "mn", "mo",
        "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na", "ne", "ng", "ni",
        "nl", "no", "np", "nz", "om", "pa", "pe", "pg", "ph", "pk", "pl", "pt",
        "pw", "py", "qa", "ro", "rs", "rw", "sa", "sb", "sc", "se", "sg", "si",
        "sk", "sl", "sn", "sr", "st", "sv", "sz", "td", "th", "tj", "tm", "tn",
        "to", "tr", "tt", "tw", "tz", "ua", "ug", "us", "uy", "uz", "vc", "ve",
        "vg", "vn", "ye", "za", "zw",
    ].map { AppStoreCountry(code: $0) }

    private static let preferredCodes = [
        "cn", "hk", "tw", "jp", "sg", "us", "gb", "kr", "ca", "au", "de", "fr", "it", "es", "th", "tr", "is"
    ]

    static var menuOrder: [AppStoreCountry] {
        let preferred = preferredCodes.compactMap { code in
            all.first { $0.code == code }
        }
        let preferredSet = Set(preferredCodes)
        let remaining = all
            .filter { !preferredSet.contains($0.code) }
            .sorted { $0.name.localizedCompare($1.name) == .orderedAscending }
        return preferred + remaining
    }

    static func named(_ code: String) -> AppStoreCountry {
        let cleanCode = code.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return all.first { $0.code == cleanCode } ?? all.first { $0.code == "cn" } ?? all[0]
    }
}

private extension String {
    var containsCJKIdeograph: Bool {
        unicodeScalars.contains { scalar in
            (0x4E00...0x9FFF).contains(Int(scalar.value))
        }
    }
}

@MainActor
final class CatalogViewModel: ObservableObject {
    @Published var searchQuery = ""
    @Published var country = "cn"
    @Published var platform = AppSearchPlatform.iphone.rawValue
    @Published var searchResults: [AppSearchResult] = []
    @Published var selectedSearchID: String?
    @Published var searchStatus = String(localized: "正在加载 App...")
    @Published var isSearching = false
    @Published var isLoadingMoreFeatured = false
    @Published var isShowingFeatured = true
    @Published var canLoadMoreFeatured = false

    @Published var historyAppID = ""
    @Published var historyProvider = "auto"
    @Published var versionResults: [VersionRecord] = []
    @Published var selectedVersionID: String?
    @Published var versionStatus = String(localized: "输入 App ID 以查询历史版本。")
    @Published var isLoadingVersions = false

    var selectedSearchResult: AppSearchResult? {
        searchResults.first { $0.id == selectedSearchID }
    }

    var selectedVersion: VersionRecord? {
        versionResults.first { $0.id == selectedVersionID }
    }

    private var searchSequence = 0
    private let featuredPageSize = 200
    private var featuredOffset = 0

    private var cleanCountry: String {
        let value = country.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return value.isEmpty ? "cn" : value
    }

    private var cleanPlatform: String {
        AppSearchPlatform.named(platform).rawValue
    }

    private func nextSearchSequence() -> Int {
        searchSequence += 1
        return searchSequence
    }

    func search() {
        let query = searchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else {
            loadFeatured()
            return
        }

        let country = cleanCountry
        let platform = cleanPlatform
        let sequence = nextSearchSequence()
        isSearching = true
        isShowingFeatured = false
        canLoadMoreFeatured = false
        searchStatus = String(localized: "正在搜索...")
        selectedSearchID = nil

        Task {
            do {
                let data = try await NodeRuntime.runJSON(arguments: [
                    "main.js", "search",
                    "--query", query,
                    "--country", country,
                    "--platform", platform,
                    "--limit", "30"
                ])
                let response = try JSONDecoder().decode(SearchResponse.self, from: data)
                guard sequence == searchSequence else { return }
                searchResults = response.results
                searchStatus = response.count == 0 ? String(localized: "没有找到结果。") : String(localized: "找到 \(response.count) 个结果。")
            } catch {
                guard sequence == searchSequence else { return }
                searchResults = []
                searchStatus = String(localized: "搜索失败：\(error.localizedDescription)")
            }
            isSearching = false
        }
    }

    func loadFeatured() {
        let country = cleanCountry
        let platform = cleanPlatform
        let sequence = nextSearchSequence()
        isSearching = true
        isLoadingMoreFeatured = false
        isShowingFeatured = true
        canLoadMoreFeatured = false
        featuredOffset = 0
        selectedSearchID = nil
        searchStatus = String(localized: "正在加载 App...")

        Task {
            var lastError: Error?
            for attempt in 0..<2 {
                if attempt > 0 {
                    guard sequence == searchSequence else { return }
                    searchStatus = String(localized: "正在重试加载 App...")
                    try? await Task.sleep(nanoseconds: 350_000_000)
                }
                do {
                    let data = try await NodeRuntime.runJSON(arguments: [
                        "main.js", "featured",
                        "--country", country,
                        "--platform", platform,
                        "--limit", "\(featuredPageSize)",
                        "--offset", "0"
                    ], timeout: 15)
                    let response = try JSONDecoder().decode(SearchResponse.self, from: data)
                    guard sequence == searchSequence else { return }
                    searchResults = response.results
                    canLoadMoreFeatured = response.hasMore ?? false
                    featuredOffset = (response.offset ?? 0) + (response.limit ?? featuredPageSize)
                    searchStatus = response.results.isEmpty ? String(localized: "没有找到 App。") : String(localized: "已载入 \(searchResults.count) 个 App。")
                    isSearching = false
                    return
                } catch {
                    lastError = error
                    guard sequence == searchSequence else { return }
                }
            }
            searchResults = []
            canLoadMoreFeatured = false
            searchStatus = String(localized: "App 列表加载失败：\(lastError?.localizedDescription ?? "")")
            isSearching = false
        }
    }

    func loadMoreFeaturedIfNeeded(current result: AppSearchResult) {
        guard isShowingFeatured, canLoadMoreFeatured, !isSearching, !isLoadingMoreFeatured else { return }
        guard searchResults.suffix(6).contains(where: { $0.id == result.id }) else { return }

        let country = cleanCountry
        let platform = cleanPlatform
        let sequence = searchSequence
        let offset = featuredOffset
        isLoadingMoreFeatured = true
        searchStatus = String(localized: "正在加载更多 App...")

        Task {
            do {
                let data = try await NodeRuntime.runJSON(arguments: [
                    "main.js", "featured",
                    "--country", country,
                    "--platform", platform,
                    "--limit", "\(featuredPageSize)",
                    "--offset", "\(offset)"
                ])
                let response = try JSONDecoder().decode(SearchResponse.self, from: data)
                guard sequence == searchSequence else { return }
                let existingIDs = Set(searchResults.map(\.id))
                searchResults.append(contentsOf: response.results.filter { !existingIDs.contains($0.id) })
                canLoadMoreFeatured = response.hasMore ?? false
                featuredOffset = (response.offset ?? offset) + (response.limit ?? featuredPageSize)
                searchStatus = String(localized: "已载入 \(searchResults.count) 个热门 App。")
            } catch {
                guard sequence == searchSequence else { return }
                canLoadMoreFeatured = false
                searchStatus = String(localized: "加载更多失败：\(error.localizedDescription)")
            }
            isLoadingMoreFeatured = false
        }
    }

    func loadVersions() {
        let cleanAppID = historyAppID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanAppID.isEmpty else {
            versionStatus = String(localized: "请输入 App ID。")
            return
        }

        isLoadingVersions = true
        versionStatus = String(localized: "正在查询历史版本...")
        selectedVersionID = nil
        versionResults = []

        Task {
            do {
                let data = try await NodeRuntime.runJSON(arguments: [
                    "main.js", "versions",
                    "--id", cleanAppID,
                    "--provider", historyProvider
                ])
                let response = try JSONDecoder().decode(VersionsResponse.self, from: data)
                versionResults = response.versions

                if response.count == 0 {
                    let detail = response.errors.isEmpty ? "" : " \(response.errors.joined(separator: "；"))"
                    versionStatus = String(localized: "没有查询到历史版本。\(detail)")
                } else {
                    versionStatus = String(localized: "找到 \(response.count) 个历史版本，来源：\(response.provider)。")
                }
            } catch {
                versionResults = []
                versionStatus = String(localized: "查询失败：\(error.localizedDescription)")
            }
            isLoadingVersions = false
        }
    }
}

enum RightPanelMode: String, CaseIterable, Identifiable {
    case search
    case versions
    case download
    case logs

    static let allCases: [RightPanelMode] = [.search, .download]

    var id: String { rawValue }

    var title: String {
        switch self {
        case .search:
            return String(localized: "搜索")
        case .versions:
            return String(localized: "历史版本")
        case .download:
            return String(localized: "下载")
        case .logs:
            return String(localized: "日志")
        }
    }

    var systemImage: String {
        switch self {
        case .search:
            return "magnifyingglass"
        case .versions:
            return "clock.arrow.circlepath"
        case .download:
            return "arrow.down.circle"
        case .logs:
            return "terminal"
        }
    }
}

struct ContentView: View {
    private enum ManualActionState: Hashable {
        case error
        case running
        case downloaded
        case ready
    }

    private enum DownloadSelectionScope {
        case appGroups
        case versions
    }

    private enum ActiveField: Hashable {
        case search
        case manualAppID
        case manualVersionID
    }

    @EnvironmentObject private var accountStore: AccountStore
    @Environment(\.openWindow) private var openWindow
    @StateObject private var downloads = DownloadManager()
    @StateObject private var catalog = CatalogViewModel()

    @State private var rightPanel = RightPanelMode.search
    @State private var pendingVerificationCode = ""
    @State private var showingVerificationPrompt = false
    @State private var pendingCodeJobID: String?
    @State private var saveMessage = ""
    @State private var didLoadCredentials = false
    @State private var hoveredMode: RightPanelMode?
    @State private var selectedApp: AppSearchResult?
    @State private var selectedAppLocalIconPath: String?
    @State private var selectedVersion: VersionRecord?
    @State private var selectedVersionIDs: Set<String> = []
    @State private var lastSelectedVersionID: String?
    @State private var downloadedFiles: [String: URL] = [:]
    @State private var versionIcons: [String: NSImage] = [:]
    @State private var remoteAppIcons: [String: NSImage] = [:]
    @State private var downloadedVersionIDs: [String: URL] = [:]
    @State private var downloadedItems: [DownloadedItem] = []
    @State private var noUpdateSelections: [String: Bool] = [:]
    @State private var selectedDownloadedItemID: String?
    @State private var selectedDownloadedItemIDs: Set<String> = []
    @State private var lastSelectedDownloadedItemID: String?
    @State private var selectedDownloadedGroupID: String?
    @State private var selectedDownloadedGroupIDs: Set<String> = []
    @State private var lastSelectedDownloadedGroupID: String?
    @State private var downloadSelectionScope: DownloadSelectionScope = .appGroups
    @State private var downloadSearchQuery = ""
    @State private var expandedGroups: Set<String> = []
    @State private var manualAppID = ""
    @State private var manualVersionID = ""
    @State private var manualNoUpdate = false
    @State private var manualLatestDownloadedPath: String?
    @State private var manualLatestDownloadedJobID: String?
    @State private var appleVersionFetchNeedsAcquisition = false
    @State private var storefrontReloadTask: Task<Void, Never>?
    @Namespace private var manualActionGlassNamespace
    @Environment(\.colorScheme) private var colorScheme
    @FocusState private var activeField: ActiveField?

    @AppStorage("downloadAppId") private var downloadAppID = ""
    @AppStorage("downloadVersionId") private var downloadVersionID = ""
    @AppStorage("downloadDir") private var downloadDir = ""
    @AppStorage("catalogCountry") private var selectedCountryCode = "cn"
    @AppStorage("catalogSearchPlatform") private var selectedSearchPlatformID = AppSearchPlatform.iphone.rawValue
    @AppStorage(AppLanguage.overrideKey) private var languageOverride = ""

    private var versionListLoading: Bool {
        catalog.isLoadingVersions || downloads.isRunning(Self.versionIDsFetchJobKey)
    }

    private var centeredSpinner: some View {
        ProgressView()
            .controlSize(.large)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var anyRunning: Bool { downloads.anyRunning }
    private var activeLog: String { downloads.focusJob?.log ?? "" }
    private var activeStatus: String { downloads.anyRunning ? String(localized: "运行中") : (downloads.focusJob?.status.displayName ?? String(localized: "就绪")) }
    private func versionIsRunning(_ id: String?) -> Bool { id.map { downloads.isRunning($0) } ?? false }
    private func noUpdateEnabled(for record: VersionRecord) -> Bool {
        noUpdateSelections[record.versionId.isEmpty ? record.id : record.versionId] ?? false
    }
    private func setNoUpdateEnabled(_ enabled: Bool, for record: VersionRecord) {
        noUpdateSelections[record.versionId.isEmpty ? record.id : record.versionId] = enabled
    }
    private func downloadJobID(for record: VersionRecord, removesAppStoreUpdates: Bool) -> String {
        "\(record.id)-\(IPADownloadVariant(removeAppStoreUpdateMetadata: removesAppStoreUpdates).rawValue)"
    }
    private func selectedDownloadJobID() -> String? {
        guard let selectedVersion else { return nil }
        return downloadJobID(for: selectedVersion, removesAppStoreUpdates: noUpdateEnabled(for: selectedVersion))
    }

    var body: some View {
        mainWorkspace
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .toolbar {
                ToolbarItem(placement: .principal) {
                    floatingModeBar
                }
                .sharedBackgroundVisibility(.hidden)

                ToolbarItem(placement: .primaryAction) {
                    toolbarSupportButton
                }
                .sharedBackgroundVisibility(.hidden)

                ToolbarItem(placement: .primaryAction) {
                    toolbarSettingsButton
                }
                .sharedBackgroundVisibility(.hidden)
            }
            .toolbar(removing: .title)
        .background(appBackground)
        .background(
            FocusReleaseClickMonitor(
                isEditing: Binding(
                    get: { activeField != nil },
                    set: { editing in
                        if !editing {
                            activeField = nil
                            KeyboardShortcutState.shared.isTextEditing = false
                        }
                    }
                )
            )
            .frame(width: 0, height: 0)
        )
        .background(WindowChromeConfigurator())
        .frame(minWidth: 1100, minHeight: 680)
        .onAppear(perform: loadSavedValuesOnce)
        .onAppear { refreshDownloadedFiles() }
        .onAppear {
            ApplicationKeyboardShortcutInterceptor.install()
            KeyboardShortcutState.shared.isTextEditing = activeField != nil
        }
        .onReceive(NotificationCenter.default.publisher(for: .pastelSelectAllRows)) { _ in
            handleSelectAllShortcut()
        }
        .onReceive(NotificationCenter.default.publisher(for: .pastelRefreshActivePanel)) { _ in
            handleRefreshShortcut()
        }
        .onChange(of: activeField) { _, field in
            KeyboardShortcutState.shared.isTextEditing = field != nil
        }
        .onChange(of: accountStore.selectedAccountID) { _, _ in
            let country = accountStore.selectedAccount?.countryCode ?? selectedCountryCode
            storefrontReloadTask?.cancel()
            storefrontReloadTask = Task { @MainActor in
                try? await Task.sleep(nanoseconds: 350_000_000)
                guard !Task.isCancelled else { return }
                applyStorefrontCountry(country, reload: true)
            }
        }
        .onChange(of: downloads.runningCount) { _, _ in
            refreshDownloadedFiles()
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                refreshDownloadedFiles()
            }
        }
        .onChange(of: downloads.codeNeededJobID) { _, jobID in
            if let jobID, !showingVerificationPrompt {
                pendingCodeJobID = jobID
                pendingVerificationCode = ""
                showingVerificationPrompt = true
            }
        }
        .onChange(of: downloadDir) { _, _ in refreshDownloadedFiles() }
        .onChange(of: catalog.versionResults) { _, results in
            refreshDownloadedFiles()
            let validIDs = Set(results.map(\.id))
            selectedVersionIDs.formIntersection(validIDs)
            if let lastSelectedVersionID, !validIDs.contains(lastSelectedVersionID) {
                self.lastSelectedVersionID = nil
            }
            if let selectedVersion, !validIDs.contains(selectedVersion.id) {
                self.selectedVersion = nil
                downloadVersionID = ""
                catalog.selectedVersionID = nil
            }
        }
        .onChange(of: rightPanel) { _, panel in if panel == .download { refreshDownloadedFiles() } }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            refreshDownloadedFiles()
        }
        .onChange(of: downloads.job(Self.versionIDsFetchJobKey)?.status) { _, status in
            guard let job = downloads.job(Self.versionIDsFetchJobKey) else { return }
            if status == .done || (status == .failed && !job.needsCode) {
                parseFetchedVersionIDs(from: job.log)
                downloads.remove(id: Self.versionIDsFetchJobKey)
            }
        }
        .alert(String(localized: "双重认证"), isPresented: $showingVerificationPrompt) {
            TextField(String(localized: "验证码"), text: $pendingVerificationCode)
            Button(String(localized: "继续")) {
                submitVerificationCode()
            }
            Button(String(localized: "取消"), role: .cancel) {
                pendingVerificationCode = ""
            }
        } message: {
            Text(String(localized: "验证码已发送至你的受信任 Apple 设备。输入后将完成双重认证并继续。"))
        }
    }

    private var appBackground: some View {
        Rectangle()
            .fill(.windowBackground)
            .ignoresSafeArea()
    }

    private var toolbarSettingsButton: some View {
        Button {
            showSettings()
        } label: {
            Image(systemName: "gear")
                .font(.system(size: 15, weight: .regular))
                .frame(width: 35, height: 35)
                .contentShape(Circle())
                .glassEffect(.regular.interactive(), in: Circle())
        }
        .buttonStyle(.plain)
    }

    private var toolbarSupportButton: some View {
        Button {
            openAuthorGitHub()
        } label: {
            Image(systemName: "heart.fill")
                .font(.system(size: 14, weight: .regular))
                .foregroundStyle(.red)
                .frame(width: 35, height: 35)
                .contentShape(Circle())
                .glassEffect(.regular.interactive(), in: Circle())
        }
        .buttonStyle(.plain)
    }

    private func showSettings() {
        openWindow(id: "settings")
    }

    private func openAuthorGitHub() {
        if let url = URL(string: "https://github.com/EEliberto/IPA-Download") {
            NSWorkspace.shared.open(url)
        }
    }

    private var floatingModeBar: some View {
        GlassEffectContainer(spacing: 6) {
            HStack(spacing: 0) {
                ForEach(Array(RightPanelMode.allCases.enumerated()), id: \.element.id) { index, mode in
                    Button {
                        rightPanel = mode
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: mode.systemImage)
                                .font(.system(size: 14.5, weight: .regular))
                            Text(mode.title)
                                .font(.system(size: 13.2, weight: .regular))
                        }
                            .frame(minHeight: 27)
                            .padding(.horizontal, 16)
                            .fixedSize(horizontal: true, vertical: false)
                            .contentShape(Capsule())
                            .background {
                                if rightPanel == mode {
                                    Capsule()
                                        .fill(modeSelectionFill)
                                } else if hoveredMode == mode {
                                    Capsule()
                                        .fill(modeHoverFill)
                                }
                            }
                    }
                    .buttonStyle(StablePressButtonStyle())
                    .foregroundStyle(rightPanel == mode ? modeSelectionText : Color.secondary)
                    .onHover { isHovering in
                        if isHovering {
                            hoveredMode = mode
                        } else if hoveredMode == mode {
                            hoveredMode = nil
                        }
                    }

                    if index < RightPanelMode.allCases.count - 1 {
                        Rectangle()
                            .fill(modeDividerColor)
                            .frame(width: 1, height: 18)
                            .padding(.horizontal, 2)
                            .opacity(shouldShowModeDivider(after: index) ? 1 : 0)
                    }
                }
            }
            .padding(4)
            .background {
                Capsule()
                    .fill(modeBarBaseFill)
                    .shadow(color: modeBarShadow, radius: modeBarShadowRadius, x: 0, y: modeBarShadowY)
            }
            .overlay {
                Capsule()
                    .stroke(modeBarStroke, lineWidth: 1)
            }
            .glassEffect(.regular.tint(modeBarGlassTint).interactive(), in: Capsule())
        }
    }

    private var modeSelectionFill: Color {
        colorScheme == .dark ? Color.white.opacity(0.24) : Color.black.opacity(0.065)
    }

    private var modeHoverFill: Color {
        colorScheme == .dark ? Color.white.opacity(0.14) : Color.black.opacity(0.04)
    }

    private var modeSelectionText: Color {
        colorScheme == .dark ? Color.white : Color.primary
    }

    private var modeDividerColor: Color {
        colorScheme == .dark ? Color.white.opacity(0.17) : Color(nsColor: .separatorColor).opacity(0.38)
    }

    private var modeBarBaseFill: Color {
        colorScheme == .dark ? Color.white.opacity(0.045) : Color.white.opacity(0.68)
    }

    private var modeBarGlassTint: Color {
        colorScheme == .dark ? Color(red: 0.10, green: 0.12, blue: 0.16).opacity(0.34) : Color.white.opacity(0.44)
    }

    private var modeBarStroke: Color {
        colorScheme == .dark ? Color.white.opacity(0.16) : Color.black.opacity(0.04)
    }

    private var modeBarShadow: Color {
        colorScheme == .dark ? Color.black.opacity(0.18) : Color.black.opacity(0.09)
    }

    private var modeBarShadowRadius: CGFloat {
        colorScheme == .dark ? 9 : 16
    }

    private var modeBarShadowY: CGFloat {
        colorScheme == .dark ? 5 : 8
    }

    private func shouldShowModeDivider(after index: Int) -> Bool {
        let modes = RightPanelMode.allCases
        guard index < modes.count - 1 else { return false }
        return modes[index] != rightPanel
            && modes[index + 1] != rightPanel
            && modes[index] != hoveredMode
            && modes[index + 1] != hoveredMode
    }

    private var mainWorkspace: some View {
        Group {
            switch rightPanel {
            case .search:
                libraryWorkspace
            case .versions:
                versionsWorkspace
                    .padding(.top, 82)
                    .padding(.horizontal, 34)
                    .padding(.bottom, 30)
                    .frame(maxWidth: 1220, maxHeight: .infinity)
            case .download:
                libraryWorkspace
            case .logs:
                logsWorkspace
                    .padding(.top, 82)
                    .padding(.horizontal, 34)
                    .padding(.bottom, 30)
                    .frame(maxWidth: 1220, maxHeight: .infinity)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var activeAppID: String {
        selectedApp?.id ?? downloadAppID.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var activeAppName: String {
        if let selectedApp {
            return selectedApp.name
        }
        return activeAppID.isEmpty ? String(localized: "未选择 App") : "App ID \(activeAppID)"
    }

    private var manualAppIDTrimmed: String {
        manualAppID.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var manualVersionIDTrimmed: String {
        manualVersionID.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var canDownloadManualVersion: Bool {
        !manualAppIDTrimmed.isEmpty && !downloadDir.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private var manualDownloadVariant: IPADownloadVariant {
        IPADownloadVariant(removeAppStoreUpdateMetadata: manualNoUpdate)
    }

    private var manualDownloadJobID: String {
        let versionKey = manualVersionIDTrimmed.isEmpty ? "latest" : manualVersionIDTrimmed
        return "manual-\(manualAppIDTrimmed)-\(versionKey)-\(manualDownloadVariant.rawValue)"
    }

    private var manualDownloadJob: DownloadManager.Job? {
        downloads.job(manualDownloadJobID)
    }

    private var manualDownloadedURL: URL? {
        if manualVersionIDTrimmed.isEmpty {
            guard manualLatestDownloadedJobID == manualDownloadJobID,
                  let path = manualLatestDownloadedPath,
                  FileManager.default.fileExists(atPath: path) else {
                return nil
            }
            return URL(fileURLWithPath: path)
        }

        return downloadedItems.first(where: { item in
            item.versionId == manualVersionIDTrimmed
                && item.removesAppStoreUpdates == manualDownloadVariant.removesAppStoreUpdates
                && (manualAppIDTrimmed.isEmpty || item.appId == manualAppIDTrimmed)
        })?.fileURL
    }

    private var manualActionState: ManualActionState {
        if manualDownloadJob?.status == .failed { return .error }
        if downloads.isRunning(manualDownloadJobID) { return .running }
        if manualDownloadedURL != nil { return .downloaded }
        return .ready
    }

    private var selectedAppLocalIcon: NSImage? {
        selectedAppLocalIconPath.flatMap { versionIcons[$0] }
    }

    private var libraryWorkspace: some View {
        NavigationSplitView {
            Group {
                if rightPanel == .download {
                    downloadLibrarySidebar
                } else {
                    appSidebar
                }
            }
            .navigationSplitViewColumnWidth(min: 310, ideal: 340, max: 380)
        } detail: {
            Group {
                if rightPanel == .download {
                    downloadDetailPane
                } else {
                    appHistoryDetailPane
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(.top, 12)
            .padding(.leading, 14)
            .padding(.trailing, 14)
            .padding(.bottom, 12)
        }
        .navigationSplitViewStyle(.balanced)
        .toolbar(removing: .sidebarToggle)
    }

    private var searchWorkspace: some View {
        NavigationSplitView {
            appSidebar
                .navigationSplitViewColumnWidth(min: 310, ideal: 340, max: 380)
        } detail: {
            appHistoryDetailPane
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(.top, 12)
                .padding(.leading, 14)
                .padding(.trailing, 14)
                .padding(.bottom, 4)
        }
        .navigationSplitViewStyle(.balanced)
        .toolbar(removing: .sidebarToggle)
    }

    @ViewBuilder
    private var searchScrollContent: some View {
        ScrollView {
            if catalog.searchResults.isEmpty {
                largeEmptyState(
                    systemImage: "magnifyingglass",
                    title: catalog.isSearching ? String(localized: "正在加载") : String(localized: "暂无内容"),
                    message: catalog.searchStatus
                )
                .padding(.top, 46)
            } else {
                VStack(alignment: .leading, spacing: 18) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(catalog.isShowingFeatured ? String(localized: "热门 App") : String(localized: "搜索结果"))
                            .font(.title2.weight(.semibold))
                        Spacer()
                        Text(String(localized: "\(catalog.searchResults.count) 个结果"))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }

                    LazyVGrid(columns: searchGridColumns, spacing: 18) {
                        ForEach(Array(catalog.searchResults.enumerated()), id: \.element.id) { index, result in
                            Button {
                                selectApp(result)
                            } label: {
                                AppSearchTile(
                                    rank: index + 1,
                                    result: result,
                                    isSelected: selectedApp?.id == result.id
                                )
                            }
                            .buttonStyle(.plain)
                            .onAppear {
                                catalog.loadMoreFeaturedIfNeeded(current: result)
                            }
                            .contextMenu {
                                if let url = URL(string: result.trackViewUrl), !result.trackViewUrl.isEmpty {
                                    Button(String(localized: "打开 App Store")) {
                                        NSWorkspace.shared.open(url)
                                    }
                                }
                            }
                        }
                    }

                    if catalog.isLoadingMoreFeatured {
                        HStack(spacing: 8) {
                            ProgressView()
                                .controlSize(.small)
                            Text(String(localized: "正在加载更多"))
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.top, 4)
                    }
                }
                .padding(.horizontal, 46)
                .padding(.top, 16)
                .padding(.bottom, 96)
            }
        }
        .contentMargins(.bottom, 92, for: .scrollContent)
        .contentMargins(.trailing, 0, for: .scrollIndicators)
    }

    private var appSidebar: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline) {
                    Text(catalog.isShowingFeatured ? String(localized: "热门 App") : String(localized: "搜索结果"))
                        .font(.headline.weight(.semibold))
                    Spacer()
                    Text(String(localized: "\(catalog.searchResults.count) 条结果"))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .padding(.leading, 4)
                .padding(.trailing, 12)

                if catalog.isSearching {
                    centeredSpinner
                        .frame(minHeight: 260)
                } else if catalog.searchResults.isEmpty {
                    largeEmptyState(
                        systemImage: "magnifyingglass",
                        title: String(localized: "暂无内容"),
                        message: catalog.searchStatus
                    )
                    .frame(maxWidth: .infinity, minHeight: 260)
                } else {
                    LazyVStack(spacing: 4) {
                        ForEach(Array(catalog.searchResults.enumerated()), id: \.element.id) { index, result in
                            Button {
                                selectApp(result)
                            } label: {
                                AppSidebarRow(
                                    rank: index + 1,
                                    result: result,
                                    isSelected: selectedApp?.id == result.id
                                )
                            }
                            .buttonStyle(StablePressButtonStyle())
                            .onAppear {
                                catalog.loadMoreFeaturedIfNeeded(current: result)
                            }
                            .contextMenu {
                                if let url = URL(string: result.trackViewUrl), !result.trackViewUrl.isEmpty {
                                    Button(String(localized: "打开 App Store")) {
                                        NSWorkspace.shared.open(url)
                                    }
                                }
                            }
                        }

                        if catalog.isLoadingMoreFeatured {
                            HStack(spacing: 8) {
                                ProgressView()
                                    .controlSize(.small)
                                Text(String(localized: "正在加载更多"))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                        }
                    }
                    .padding(.trailing, 12)
                }
            }
            .padding(.top, 8)
            .padding(.horizontal, 18)
            .padding(.bottom, 34)
        }
        .safeAreaBar(edge: .top, spacing: 8) {
            sidebarSearchPanel
            .padding(.horizontal, 18)
        }
        .scrollEdgeEffectStyle(.soft, for: .top)
        .contentMargins(.trailing, 0, for: .scrollIndicators)
        .frame(maxHeight: .infinity, alignment: .top)
    }

    private var sidebarScrollMask: some View {
        VStack(spacing: 0) {
            Rectangle().fill(Color.black)
            LinearGradient(colors: [Color.black, Color.clear], startPoint: .top, endPoint: .bottom)
                .frame(height: 22)
        }
    }

    private var sidebarSearchPanel: some View {
        VStack(spacing: 10) {
            sidebarSearchControls
            sidebarPlatformPicker
        }
        .frame(maxWidth: .infinity)
    }

    private var sidebarSearchControls: some View {
        HStack(spacing: 0) {
            sidebarCountryMenu

            Rectangle()
                .fill(Color(nsColor: .separatorColor).opacity(0.32))
                .frame(width: 1, height: 18)
                .padding(.horizontal, 8)

            Image(systemName: "magnifyingglass")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(.secondary)
                .frame(width: 18, height: 18)

            TextField(String(localized: "搜索 App"), text: $catalog.searchQuery)
                .textFieldStyle(.plain)
                .font(.callout)
                .focused($activeField, equals: .search)
                .lineLimit(1)
                .onSubmit {
                    catalog.search()
                }
                .padding(.leading, 8)

            if !catalog.searchQuery.isEmpty {
                Button {
                    catalog.searchQuery = ""
                    activeField = nil
                    catalog.loadFeatured()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(.secondary)
                        .symbolRenderingMode(.hierarchical)
                        .frame(width: 20, height: 20)
                }
                .buttonStyle(StablePressButtonStyle())
            }

        }
        .padding(.leading, 12)
        .padding(.trailing, catalog.searchQuery.isEmpty ? 16 : 11)
        .frame(height: 42)
        .frame(maxWidth: .infinity)
        .contentShape(Capsule())
        .glassEffect(.regular.tint(searchControlGlassTint).interactive(), in: Capsule())
        .background(searchControlFill, in: Capsule())
        .overlay {
            Capsule()
                .stroke(Color(nsColor: .separatorColor).opacity(0.18), lineWidth: 1)
        }
    }

    private var sidebarPlatformPicker: some View {
        HStack(spacing: 0) {
            ForEach(Array(AppSearchPlatform.allCases.enumerated()), id: \.element.id) { index, platform in
                let isSelected = selectedSearchPlatform == platform
                Button {
                    selectSearchPlatform(platform)
                } label: {
                    HStack(spacing: 7) {
                        Image(systemName: platform.symbolName)
                            .font(.system(size: platform == .vision ? 13 : 14, weight: .semibold))
                            .symbolRenderingMode(.hierarchical)
                            .frame(width: 18, height: 18)

                        Text(platform.title)
                            .font(.callout)
                            .lineLimit(1)
                    }
                    .frame(minWidth: 84, minHeight: 30)
                    .padding(.horizontal, 10)
                    .foregroundStyle(isSelected ? Color.white : Color.secondary)
                    .background {
                        if isSelected {
                            Capsule()
                                .fill(Color(nsColor: .selectedContentBackgroundColor))
                        }
                    }
                    .contentShape(Capsule())
                }
                .buttonStyle(StablePressButtonStyle())

                if index < AppSearchPlatform.allCases.count - 1 {
                    Rectangle()
                        .fill(Color(nsColor: .separatorColor).opacity(0.24))
                        .frame(width: 1, height: 18)
                        .padding(.horizontal, 2)
                        .opacity(isSelected || selectedSearchPlatform == AppSearchPlatform.allCases[index + 1] ? 0 : 1)
                }
            }
        }
        .padding(3)
        .frame(height: 36)
        .fixedSize(horizontal: true, vertical: false)
        .glassEffect(.regular.tint(searchControlGlassTint).interactive(), in: Capsule())
        .background(searchControlFill, in: Capsule())
        .overlay {
            Capsule()
                .stroke(Color(nsColor: .separatorColor).opacity(0.16), lineWidth: 1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var sidebarCountryMenu: some View {
        Menu {
            ForEach(AppStoreCountry.menuOrder) { country in
                Button {
                    selectCountry(country)
                } label: {
                    if country.code == selectedCountry.code {
                        Label(country.name, systemImage: "checkmark")
                    } else {
                        Text(country.name)
                    }
                }
            }
        } label: {
            HStack(spacing: 5) {
                Image(systemName: "globe")
                    .font(.system(size: 14, weight: .semibold))
                    .frame(width: 18, height: 18)

                Text(selectedCountry.name)
                    .font(.callout.weight(.semibold))
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .frame(width: compactCountryNameWidth, height: 20, alignment: .center)

                Image(systemName: "chevron.down")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(.tertiary)
                    .frame(width: 12, height: 18)
            }
            .foregroundStyle(.secondary)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder
    private var appHistoryDetailPane: some View {
        if activeAppID.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                Text(String(localized: "选择 App 以继续。"))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)

                historyMetadataBar
            }
            .padding(10)
            .frame(maxHeight: .infinity, alignment: .top)
        } else {
            VStack(alignment: .leading, spacing: 0) {
                appHistoryHeader
                    .padding(.bottom, 10)
                    .zIndex(1)

                Group {
                    if visionHistoryNeedsAppleSource {
                        VStack(spacing: 14) {
                            largeEmptyState(
                                systemImage: "vision.pro",
                                title: String(localized: "Apple Vision Pro"),
                                message: String(localized: "Apple Vision Pro 的 App 历史版本目前仅在 Apple 来源提供，其他来源并未收录。"),
                                fills: false
                            )

                            Button {
                                selectHistoryProvider("apple")
                            } label: {
                                Text(String(localized: "前往 Apple 来源获取"))
                            }
                            .buttonStyle(.glassProminent)
                            .controlSize(.large)
                            .disabled(catalog.isLoadingVersions)
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    } else if versionListLoading {
                        centeredSpinner
                    } else if catalog.versionResults.isEmpty {
                        VStack(spacing: 14) {
                            if appleVersionFetchNeedsAcquisition {
                                largeEmptyState(
                                    systemImage: "app.badge",
                                    title: String(localized: "需要获取 App"),
                                    message: String(localized: "此 Apple 账户未拥有此 App，是否从 Apple 获取此 App？"),
                                    fills: false
                                )

                                Button {
                                    fetchVersionIDsFromApple(allowAppAcquisition: true)
                                } label: {
                                    Text(String(localized: "获取"))
                                }
                                .buttonStyle(.glassProminent)
                                .controlSize(.large)
                                .disabled(catalog.isLoadingVersions)
                            } else {
                                largeEmptyState(
                                    systemImage: "clock.arrow.circlepath",
                                    title: catalog.isLoadingVersions ? String(localized: "正在查询") : String(localized: "等待历史版本"),
                                    message: catalog.versionStatus,
                                    fills: false
                                )

                                Button {
                                    loadHistoryForActiveApp()
                                } label: {
                                    Label(String(localized: "查询历史版本"), systemImage: "arrow.clockwise")
                                }
                                .buttonStyle(.glassProminent)
                                .controlSize(.large)
                                .disabled(catalog.isLoadingVersions)
                            }
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    } else {
                        VStack(spacing: 0) {
                            ScrollView {
                                LazyVStack(alignment: .leading, spacing: 4) {
                                    ForEach(Array(catalog.versionResults.enumerated()), id: \.element.id) { index, record in
                                        let removesUpdates = noUpdateEnabled(for: record)
                                        let jobID = downloadJobID(for: record, removesAppStoreUpdates: removesUpdates)
                                        let downloadedURL = downloadedFileFor(record, removesAppStoreUpdates: removesUpdates)
                                        VersionSelectionRow(
                                            record: record,
                                            rowIndex: index,
                                            isSelected: selectedVersionIDs.contains(record.id),
                                            removesAppStoreUpdates: removesUpdates,
                                            isDownloading: downloads.isRunning(jobID),
                                            downloadProgress: downloads.job(jobID)?.progress,
                                            isPackaging: downloads.job(jobID)?.isPackaging ?? false,
                                            hasError: downloads.job(jobID)?.status == .failed,
                                            errorLog: downloads.job(jobID)?.log ?? "",
                                            downloadedURL: downloadedURL,
                                            appIcon: downloadedURL.flatMap { versionIcons[$0.path] },
                                            onSelect: {
                                                handleVersionRowSelection(record)
                                            },
                                            onToggleNoUpdate: { enabled in
                                                setNoUpdateEnabled(enabled, for: record)
                                            },
                                            onDownload: {
                                                downloadVersion(record)
                                            },
                                            onReveal: {
                                                if let url = downloadedFileFor(record, removesAppStoreUpdates: noUpdateEnabled(for: record)) { revealInFinder(url) }
                                            },
                                            onAirDrop: {
                                                if let url = downloadedFileFor(record, removesAppStoreUpdates: noUpdateEnabled(for: record)) { airDrop(url) }
                                            },
                                            onDelete: {
                                                if let url = downloadedFileFor(record, removesAppStoreUpdates: noUpdateEnabled(for: record)) { deleteDownloaded(url) }
                                            }
                                        )
                                        .contextMenu {
                                            if showsBatchDownloadMenu(for: record) {
                                                Button(String(localized: "全部下载")) {
                                                    downloadSelectedVersions()
                                                }
                                            }
                                        }
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.top, 4)
                                .padding(.bottom, 18)
                            }
                            .safeAreaBar(edge: .top, spacing: 4) {
                                versionsHeaderBar
                            }
                            .contentMargins(.bottom, 6, for: .scrollContent)
                            .contentMargins(.trailing, 0, for: .scrollIndicators)

                            versionsFooterBar
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)

                historyMetadataBar
                    .padding(.top, catalog.versionResults.isEmpty ? 10 : 0)
            }
            .padding(10)
            .frame(maxHeight: .infinity, alignment: .top)
        }
    }

    private var historyMetadataBar: some View {
        GeometryReader { proxy in
            let columns = VersionSelectionRow.columns(for: proxy.size.width)
            let alignedControlsWidth = columns.noUpdates + VersionSelectionRow.actionGap + VersionSelectionRow.actionColumnWidth
            let availableLeadingWidth = max(
                340,
                proxy.size.width - VersionSelectionRow.rowHorizontalPadding * 2 - alignedControlsWidth - 14
            )
            let leadingWidth = min(availableLeadingWidth, 560)

            HStack(alignment: .center, spacing: 0) {
                HStack(alignment: .center, spacing: 10) {
                    Image(systemName: "number.circle")
                        .font(.system(size: 16, weight: .medium))
                        .foregroundStyle(.secondary)
                        .frame(width: 24, height: 24, alignment: .center)

                    Text(String(localized: "手动获取"))
                        .font(.callout.weight(.semibold))
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)

                    manualMetadataTextField(String(localized: "App ID"), text: $manualAppID, field: .manualAppID)

                    manualMetadataTextField(String(localized: "版本 ID"), text: $manualVersionID, field: .manualVersionID)
                }
                .frame(width: leadingWidth, alignment: .leading)

                Spacer(minLength: 14)

                HStack(spacing: 0) {
                    HStack(spacing: 8) {
                        Text(String(localized: "不再更新"))
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .minimumScaleFactor(0.82)

                        manualNoUpdateControl
                            .padding(.trailing, VersionSelectionRow.noUpdatesToggleTrailingInset)
                    }
                    .frame(width: columns.noUpdates, alignment: .trailing)

                    Color.clear
                        .frame(width: VersionSelectionRow.actionGap, height: 1)

                    manualActionSlot
                }
                .frame(width: alignedControlsWidth, alignment: .trailing)
            }
            .padding(.horizontal, VersionSelectionRow.rowHorizontalPadding)
            .padding(.vertical, 6)
            .frame(width: proxy.size.width, height: 48, alignment: .leading)
            .background(manualVersionBarFill, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(Color(nsColor: .separatorColor).opacity(0.12), lineWidth: 1)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 48, maxHeight: 48, alignment: .leading)
    }

    private func manualMetadataTextField(_ prompt: String, text: Binding<String>, field: ActiveField) -> some View {
        ZStack {
            Capsule()
                .fill(manualVersionFieldFill)

            HStack(spacing: 7) {
                Text(prompt)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)

                TextField("", text: text)
                    .textFieldStyle(.plain)
                    .font(.caption.monospacedDigit())
                    .lineLimit(1)
                    .focused($activeField, equals: field)
            }
            .padding(.horizontal, 12)

            IBeamCursorRect()
                .clipShape(Capsule())
        }
            .frame(maxWidth: .infinity, minHeight: 32, maxHeight: 32)
            .overlay {
                Capsule()
                    .strokeBorder(manualVersionFieldStroke, lineWidth: 1)
            }
            .contentShape(Capsule())
            .onTapGesture {
                activeField = field
            }
            .shadow(color: manualVersionFieldShadow, radius: 2.5, x: 0, y: 1)
    }

    private var manualNoUpdateControl: some View {
        Toggle("", isOn: $manualNoUpdate)
            .labelsHidden()
            .toggleStyle(.switch)
            .controlSize(.small)
            .fixedSize()
    }

    private var manualActionSlot: some View {
        GlassEffectContainer(spacing: 0) {
            ZStack(alignment: .trailing) {
                manualActionContent
                    .id(manualActionState)
            }
        }
        .frame(width: VersionSelectionRow.actionColumnWidth, alignment: .trailing)
        .animation(.smooth(duration: 0.32), value: manualActionState)
    }

    @ViewBuilder
    private var manualActionContent: some View {
        switch manualActionState {
        case .error:
            DownloadErrorIndicator(message: manualErrorMessage, retry: downloadManualVersionID)
        case .running:
            DownloadProgressPill(progress: manualDownloadJob?.progress, isPackaging: manualDownloadJob?.isPackaging ?? false)
                .glassEffectID("manual-download-action", in: manualActionGlassNamespace)
                .glassEffectTransition(.matchedGeometry)
        case .downloaded:
            FileActionsBar(
                isSelected: false,
                onReveal: {
                    if let url = manualDownloadedURL { revealInFinder(url) }
                },
                onAirDrop: {
                    if let url = manualDownloadedURL { airDrop(url) }
                },
                onDelete: {
                    if let url = manualDownloadedURL {
                        deleteDownloaded(url)
                        if manualLatestDownloadedPath == url.path {
                            manualLatestDownloadedPath = nil
                            manualLatestDownloadedJobID = nil
                        }
                    }
                }
            )
            .glassEffectID("manual-download-action", in: manualActionGlassNamespace)
            .glassEffectTransition(.matchedGeometry)
        case .ready:
            Button {
                downloadManualVersionID()
            } label: {
                Text(String(localized: "下载"))
                    .font(.caption.weight(.semibold))
                    .frame(width: VersionSelectionRow.downloadButtonWidth, height: 26)
                    .contentShape(Capsule())
            }
            .buttonStyle(StablePressButtonStyle())
            .foregroundStyle(canDownloadManualVersion ? Color.accentColor : Color.secondary)
            .glassEffect(.regular.interactive(), in: Capsule())
            .glassEffectID("manual-download-action", in: manualActionGlassNamespace)
            .glassEffectTransition(.matchedGeometry)
            .disabled(!canDownloadManualVersion)
        }
    }

    private var manualErrorMessage: String {
        downloadErrorMessage(from: manualDownloadJob?.log ?? "")
    }

    private var panelGlassTint: Color {
        colorScheme == .dark ? Color.white.opacity(0.055) : Color.white.opacity(0.28)
    }

    private var appHeaderIconShadow: Color {
        Color.black.opacity(colorScheme == .dark ? 0.24 : 0.12)
    }

    private var manualVersionBarFill: Color {
        colorScheme == .dark ? Color.white.opacity(0.065) : Color.black.opacity(0.035)
    }

    private var manualVersionFieldFill: Color {
        colorScheme == .dark ? Color.white.opacity(0.11) : Color.white.opacity(0.82)
    }

    private var manualVersionFieldStroke: Color {
        colorScheme == .dark ? Color.white.opacity(0.18) : Color(nsColor: .separatorColor).opacity(0.14)
    }

    private var manualVersionFieldShadow: Color {
        colorScheme == .dark ? Color.black.opacity(0.28) : Color.black.opacity(0.08)
    }

    private var searchControlFill: Color {
        colorScheme == .dark ? Color.white.opacity(0.07) : Color.black.opacity(0.035)
    }

    private var searchControlGlassTint: Color {
        colorScheme == .dark ? Color(red: 0.10, green: 0.12, blue: 0.16).opacity(0.28) : Color.white.opacity(0.42)
    }

    private var appHistoryHeader: some View {
        HStack(alignment: .center, spacing: 13) {
            selectedAppHeaderIcon(size: 52)

            VStack(alignment: .leading, spacing: 3) {
                Text(activeAppName)
                    .font(.title3.weight(.semibold))
                    .lineLimit(1)
                AppIDCopyLine(appID: activeAppID, fallback: String(localized: "未选择 App"))
            }

            Spacer(minLength: 12)

            historyProviderControl
        }
        .padding(.horizontal, 2)
    }

    @ViewBuilder
    private func selectedAppHeaderIcon(size: CGFloat) -> some View {
        let cornerRadius = activeAppIsVision ? size * 0.5 : size * 0.25
        if let selectedApp, !selectedApp.artworkUrl.isEmpty {
            CachedRemoteAppIcon(urlString: selectedApp.artworkUrl,
                                size: size,
                                cornerRadius: cornerRadius,
                                cache: $remoteAppIcons)
                .shadow(color: appHeaderIconShadow, radius: 4, x: 0, y: 2)
        } else if let image = selectedAppLocalIcon {
            Image(nsImage: image)
                .resizable()
                .interpolation(.high)
                .scaledToFill()
                .frame(width: size, height: size)
                .clipShape(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .strokeBorder(Color(nsColor: .separatorColor).opacity(0.14), lineWidth: 0.5)
                }
                .shadow(color: appHeaderIconShadow, radius: 4, x: 0, y: 2)
        } else {
            Image(systemName: "app.badge")
                .font(size > 40 ? .title2 : .body)
                .foregroundStyle(.secondary)
                .frame(width: size, height: size)
                .background(.thinMaterial, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
        }
    }

    private var historyProviderControl: some View {
        HStack(spacing: 8) {
            Text(String(localized: "来源"))
                .font(.callout.weight(.semibold))
                .foregroundStyle(.primary)

            SourceProviderCapsule(
                selection: catalog.historyProvider,
                isDisabled: activeAppID.isEmpty || catalog.isLoadingVersions,
                onSelect: selectHistoryProvider
            )
            .frame(width: 360)
        }
        .fixedSize(horizontal: true, vertical: false)
    }

    private func selectHistoryProvider(_ provider: String) {
        guard catalog.historyProvider != provider else { return }
        withAnimation(.snappy(duration: 0.18)) {
            catalog.historyProvider = provider
        }
        appleVersionFetchNeedsAcquisition = false
        guard !activeAppID.isEmpty else { return }
        if activeAppIsVision && provider != "apple" {
            selectedVersion = nil
            selectedVersionIDs.removeAll()
            lastSelectedVersionID = nil
            catalog.selectedVersionID = nil
            catalog.versionResults = []
            catalog.versionStatus = String(localized: "Apple Vision Pro 的 App 历史版本目前仅在 Apple 来源提供，其他来源并未收录。")
            return
        }
        if provider == "apple" {
            fetchVersionIDsFromApple()
        } else {
            loadHistoryForActiveApp()
        }
    }

    private var searchGridColumns: [GridItem] {
        [
            GridItem(
                .adaptive(minimum: 298, maximum: 430),
                spacing: 20,
                alignment: .top
            )
        ]
    }

    private var appStoreSearchBar: some View {
        GlassEffectContainer(spacing: 12) {
            HStack(spacing: 12) {
                countryMenu

            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 18, weight: .medium))
                    .foregroundStyle(.secondary)

                TextField(String(localized: "输入 App 名称"), text: $catalog.searchQuery)
                    .textFieldStyle(.plain)
                    .font(.body)
                    .focused($activeField, equals: .search)
                    .onSubmit {
                        catalog.search()
                    }

                if !catalog.searchQuery.isEmpty {
                    Button {
                        catalog.searchQuery = ""
                        activeField = nil
                        catalog.loadFeatured()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundStyle(.secondary)
                            .symbolRenderingMode(.hierarchical)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 16)
            .frame(height: 36)
            .frame(maxWidth: .infinity)
            .glassEffect(.regular.interactive(), in: Capsule())
            .background(Color.black.opacity(0.035), in: Capsule())
            .overlay {
                Capsule()
                    .stroke(Color(nsColor: .separatorColor).opacity(0.18), lineWidth: 1)
            }

            Button {
                catalog.search()
            } label: {
                Text(String(localized: "搜索"))
                    .font(.body.weight(.semibold))
                    .frame(minWidth: 58, minHeight: 34)
            }
            .buttonStyle(.plain)
            .foregroundStyle(.white)
            .glassEffect(.regular.tint(Color.accentColor).interactive(), in: Capsule())
            .disabled(catalog.isSearching)
        }
    }
    }

    private var selectedCountry: AppStoreCountry {
        AppStoreCountry.named(selectedCountryCode)
    }

    private var compactCountryNameWidth: CGFloat {
        selectedCountry.name.containsCJKIdeograph ? 52 : 78
    }

    private var compactCountryMenuWidth: CGFloat {
        compactCountryNameWidth + 68
    }

    private var countryMenu: some View {
        Menu {
            ForEach(AppStoreCountry.menuOrder) { country in
                Button {
                    selectCountry(country)
                } label: {
                    if country.code == selectedCountry.code {
                        Label(country.name, systemImage: "checkmark")
                    } else {
                        Text(country.name)
                    }
                }
            }
        } label: {
            HStack(spacing: 5) {
                Image(systemName: "globe")
                    .font(.system(size: 14, weight: .semibold))
                    .frame(width: 18, height: 18)

                Text(selectedCountry.name)
                    .font(.body.weight(.semibold))
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .frame(width: compactCountryNameWidth, height: 20, alignment: .center)

                Image(systemName: "chevron.down")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(.tertiary)
                    .frame(width: 14, height: 18)
            }
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .frame(width: compactCountryMenuWidth, height: 36)
            .contentShape(Capsule())
            .glassEffect(.regular.interactive(), in: Capsule())
            .background(Color.black.opacity(0.035), in: Capsule())
            .overlay {
                Capsule()
                    .stroke(Color(nsColor: .separatorColor).opacity(0.18), lineWidth: 1)
            }
        }
        .buttonStyle(.plain)
    }

    private func selectCountry(_ country: AppStoreCountry) {
        selectedCountryCode = country.code
        catalog.country = country.code
        activeField = nil
        NSApp.keyWindow?.makeFirstResponder(nil)

        if let match = accountStore.accounts.first(where: { $0.countryCode.caseInsensitiveCompare(country.code) == .orderedSame }),
           match.id != accountStore.selectedAccountID {
            accountStore.select(match)
            return
        }

        if catalog.searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            catalog.loadFeatured()
        }
    }

    private var versionsWorkspace: some View {
        VStack(alignment: .leading, spacing: 22) {
            workspaceHeader(
                eyebrow: String(localized: "选择版本"),
                title: activeAppName,
                subtitle: activeAppID.isEmpty ? String(localized: "在搜索里选择一个 App。") : String(localized: "选择一个历史版本后继续。")
            )

            HStack(spacing: 14) {
                selectionPill(title: "App ID", value: activeAppID.isEmpty ? String(localized: "未选择") : activeAppID, systemImage: "app.badge")

                Picker(String(localized: "来源"), selection: $catalog.historyProvider) {
                    Text(String(localized: "自动")).tag("auto")
                    Text("Timbrd").tag("timbrd")
                    Text("Agzy").tag("agzy")
                    Text("Bilin").tag("bilin")
                }
                .pickerStyle(.segmented)
                .controlSize(.large)
                .frame(width: 330)

                Button {
                    loadHistoryForActiveApp()
                } label: {
                    Label(String(localized: "刷新"), systemImage: "arrow.clockwise")
                }
                .buttonStyle(.glass)
                .controlSize(.large)
                .disabled(activeAppID.isEmpty || catalog.isLoadingVersions)
            }

            if activeAppID.isEmpty {
                largeEmptyState(systemImage: "app.badge", title: String(localized: "未选择 App"), message: String(localized: "从搜索结果里选择一个 App。"))
            } else if versionListLoading {
                centeredSpinner
            } else if catalog.versionResults.isEmpty {
                VStack(spacing: 16) {
                    largeEmptyState(
                        systemImage: "clock.arrow.circlepath",
                        title: catalog.isLoadingVersions ? String(localized: "正在查询") : String(localized: "等待历史版本"),
                        message: catalog.versionStatus,
                        fills: false
                    )

                    Button {
                        loadHistoryForActiveApp()
                    } label: {
                        Label(String(localized: "查询历史版本"), systemImage: "clock.arrow.circlepath")
                    }
                    .buttonStyle(.glassProminent)
                    .controlSize(.large)
                    .disabled(catalog.isLoadingVersions)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 0) {
                    versionsHeader
                        .padding(.horizontal, 6)
                    Divider()
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 8) {
                            ForEach(Array(catalog.versionResults.enumerated()), id: \.element.id) { index, record in
                                let removesUpdates = noUpdateEnabled(for: record)
                                let jobID = downloadJobID(for: record, removesAppStoreUpdates: removesUpdates)
                                let downloadedURL = downloadedFileFor(record, removesAppStoreUpdates: removesUpdates)
                                VersionSelectionRow(
                                    record: record,
                                    rowIndex: index,
                                    isSelected: selectedVersionIDs.contains(record.id),
                                    removesAppStoreUpdates: removesUpdates,
                                    isDownloading: downloads.isRunning(jobID),
                                    downloadProgress: downloads.job(jobID)?.progress,
                                    isPackaging: downloads.job(jobID)?.isPackaging ?? false,
                                    hasError: downloads.job(jobID)?.status == .failed,
                                    errorLog: downloads.job(jobID)?.log ?? "",
                                    downloadedURL: downloadedURL,
                                    appIcon: downloadedURL.flatMap { versionIcons[$0.path] },
                                    onSelect: {
                                        handleVersionRowSelection(record)
                                    },
                                    onToggleNoUpdate: { enabled in
                                        setNoUpdateEnabled(enabled, for: record)
                                    },
                                    onDownload: {
                                        downloadVersion(record)
                                    },
                                    onReveal: {
                                        if let url = downloadedFileFor(record, removesAppStoreUpdates: noUpdateEnabled(for: record)) { revealInFinder(url) }
                                    },
                                    onAirDrop: {
                                        if let url = downloadedFileFor(record, removesAppStoreUpdates: noUpdateEnabled(for: record)) { airDrop(url) }
                                    },
                                    onDelete: {
                                        if let url = downloadedFileFor(record, removesAppStoreUpdates: noUpdateEnabled(for: record)) { deleteDownloaded(url) }
                                    }
                                )
                                .contextMenu {
                                    if showsBatchDownloadMenu(for: record) {
                                        Button(String(localized: "全部下载")) {
                                            downloadSelectedVersions()
                                        }
                                    }
                                }
                            }
                        }
                        .padding(.top, 10)
                    }
                }
                .padding(18)
                .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            }
        }
    }

    private var downloadWorkspace: some View {
        NavigationSplitView {
            downloadLibrarySidebar
                .navigationSplitViewColumnWidth(min: 310, ideal: 340, max: 380)
        } detail: {
            downloadDetailPane
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(.top, 12)
                .padding(.leading, 14)
                .padding(.trailing, 14)
                .padding(.bottom, 12)
        }
        .navigationSplitViewStyle(.balanced)
        .toolbar(removing: .sidebarToggle)
    }

    private var downloadedLibraryItems: [DownloadedItem] {
        downloadedItems.sorted {
            if $0.downloadDate != $1.downloadDate {
                return $0.downloadDate > $1.downloadDate
            }
            return $0.appName.localizedStandardCompare($1.appName) == .orderedAscending
        }
    }

    private var selectedDownloadedGroup: DownloadedAppGroup? {
        if let selectedDownloadedGroupID,
           let group = filteredDownloadedAppGroups.first(where: { $0.id == selectedDownloadedGroupID }) {
            return group
        }
        return filteredDownloadedAppGroups.first
    }

    private func firstSelectedDownloadedGroupID() -> String? {
        filteredDownloadedAppGroups.first { selectedDownloadedGroupIDs.contains($0.id) }?.id
    }

    private var downloadLibrarySidebar: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                downloadSidebarHeader

                if filteredDownloadedAppGroups.isEmpty {
                    Color.clear
                        .frame(maxWidth: .infinity, minHeight: 260)
                } else {
                    LazyVStack(spacing: 4) {
                        ForEach(filteredDownloadedAppGroups) { group in
                            Button {
                                handleDownloadedGroupSelection(group)
                            } label: {
                                DownloadedAppSidebarRow(
                                    group: group,
                                    icon: versionIcons[group.iconPath],
                                    isSelected: selectedDownloadedGroupIDs.contains(group.id),
                                    remoteIconCache: $remoteAppIcons
                                )
                            }
                            .buttonStyle(StablePressButtonStyle())
                            .contextMenu {
                                Button(String(localized: "删除"), role: .destructive) {
                                    if showsBatchDeleteMenu(for: group) {
                                        deleteSelectedDownloadedGroups()
                                    } else {
                                        deleteDownloadedGroup(group)
                                    }
                                }

                                Divider()

                                Button(String(localized: "在搜索中查看")) {
                                    openDownloadedGroupInSearch(group)
                                }
                            }
                        }
                    }
                    .padding(.trailing, 12)
                }
            }
            .padding(.top, 8)
            .padding(.horizontal, 18)
            .padding(.bottom, 34)
        }
        .safeAreaBar(edge: .top, spacing: 8) {
            downloadSidebarSearchControls
                .padding(.horizontal, 18)
        }
        .scrollEdgeEffectStyle(.soft, for: .top)
        .contentMargins(.trailing, 0, for: .scrollIndicators)
        .frame(maxHeight: .infinity, alignment: .top)
    }

    private var downloadSidebarHeader: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(String(localized: "已下载 App"))
                .font(.headline.weight(.semibold))
            Spacer()
            Text(String(localized: "\(filteredDownloadedAppGroups.count) 个 App"))
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .padding(.leading, 4)
        .padding(.trailing, 12)
    }

    private var downloadSidebarSearchControls: some View {
        HStack(spacing: 0) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(.secondary)
                .frame(width: 18, height: 18)

            TextField(String(localized: "搜索 App"), text: $downloadSearchQuery)
                .textFieldStyle(.plain)
                .font(.callout)
                .lineLimit(1)
                .padding(.leading, 8)

            if !downloadSearchQuery.isEmpty {
                Button {
                    downloadSearchQuery = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(.secondary)
                        .symbolRenderingMode(.hierarchical)
                        .frame(width: 20, height: 20)
                }
                .buttonStyle(StablePressButtonStyle())
            }
        }
        .padding(.leading, 12)
        .padding(.trailing, downloadSearchQuery.isEmpty ? 16 : 11)
        .frame(height: 42)
        .frame(maxWidth: .infinity)
        .contentShape(Capsule())
        .glassEffect(.regular.tint(searchControlGlassTint).interactive(), in: Capsule())
        .background(searchControlFill, in: Capsule())
        .overlay {
            Capsule()
                .stroke(Color(nsColor: .separatorColor).opacity(0.18), lineWidth: 1)
        }
    }

    private var downloadDetailPane: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let group = selectedDownloadedGroup {
                downloadedGroupHeader(group)
                    .padding(.bottom, 10)
                    .zIndex(1)

                VStack(spacing: 0) {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 4) {
                            ForEach(Array(group.items.enumerated()), id: \.element.id) { index, item in
                                DownloadedVersionHistoryRow(
                                    item: item,
                                    icon: versionIcons[item.id],
                                    rowIndex: index,
                                    isSelected: selectedDownloadedItemIDs.contains(item.id),
                                    remoteIconCache: $remoteAppIcons,
                                    onSelect: {
                                        handleDownloadedRowSelection(item)
                                    },
                                    onReveal: { revealInFinder(item.fileURL) },
                                    onAirDrop: { airDrop(item.fileURL) },
                                    onDelete: { deleteDownloaded(item.fileURL) }
                                )
                                .contextMenu {
                                    if showsBatchDeleteMenu(for: item) {
                                        Button(String(localized: "删除"), role: .destructive) {
                                            deleteSelectedDownloadedItems()
                                        }
                                    } else {
                                        Button(String(localized: "删除"), role: .destructive) {
                                            deleteDownloaded(item.fileURL)
                                        }
                                    }
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.top, 4)
                        .padding(.bottom, 18)
                    }
                    .safeAreaBar(edge: .top, spacing: 4) {
                        downloadedVersionsHeaderBar
                    }
                    .contentMargins(.bottom, 6, for: .scrollContent)
                    .contentMargins(.trailing, 0, for: .scrollIndicators)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                    downloadedVersionsFooterBar(count: group.items.count)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)

                historyMetadataBar
            } else {
                largeEmptyState(
                    systemImage: "tray.and.arrow.down",
                    title: String(localized: "暂无已下载 App"),
                    message: downloadDir.isEmpty
                        ? String(localized: "可在设置中选择保存目录。")
                        : String(localized: "下载完成后会显示在这里。")
                )

                historyMetadataBar
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func downloadedGroupHeader(_ group: DownloadedAppGroup) -> some View {
        HStack(alignment: .center, spacing: 13) {
            downloadedAppIcon(path: group.iconPath, size: 52, artworkUrl: group.artworkUrl, isVisionApp: group.isVisionApp)

            VStack(alignment: .leading, spacing: 3) {
                Text(group.appName.isEmpty ? String(localized: "未知 App") : group.appName)
                    .font(.title3.weight(.semibold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                AppIDCopyLine(
                    appID: group.appId,
                    fallback: group.developer.isEmpty ? group.bundleId : group.developer
                )
            }

            Spacer(minLength: 12)

            if !group.appId.isEmpty {
                Button {
                    openDownloadedGroupInSearch(group)
                } label: {
                    Label(String(localized: "查看版本"), systemImage: "clock.arrow.circlepath")
                        .font(.callout.weight(.semibold))
                        .padding(.horizontal, 12)
                        .frame(height: 32)
                        .contentShape(Capsule())
                }
                .buttonStyle(StablePressButtonStyle())
                .foregroundStyle(.primary)
                .glassEffect(.regular.interactive(), in: Capsule())
            }
        }
        .padding(.horizontal, 2)
    }

    private func downloadedVersionListStatusBar(count: Int) -> some View {
        ZStack {
            Text(String(localized: "已下载 \(count) 个版本"))
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity)
        .frame(height: 32, alignment: .center)
        .background(.windowBackground)
    }

    private var downloadedVersionsHeaderBar: some View {
        VStack(spacing: 0) {
            downloadedVersionsHeader
                .frame(maxWidth: .infinity, alignment: .leading)

            Divider()
        }
        .background(.windowBackground)
    }

    private func downloadedVersionsFooterBar(count: Int) -> some View {
        VStack(spacing: 0) {
            Divider()

            downloadedVersionListStatusBar(count: count)
        }
        .background(.windowBackground)
    }

    private var downloadedVersionsHeader: some View {
        GeometryReader { proxy in
            let columns = DownloadedVersionHistoryRow.columns(for: proxy.size.width)

            ZStack(alignment: .leading) {
                HStack(spacing: 0) {
                    Color.clear.frame(width: DownloadedVersionHistoryRow.iconColumnWidth, height: 1)
                    downloadedHeaderColumn(String(localized: "版本号"), width: columns.version)
                    downloadedHeaderColumn(String(localized: "版本 ID"), width: columns.versionID)
                    downloadedHeaderColumn(String(localized: "大小"), width: columns.size)
                    downloadedHeaderColumn(String(localized: "地区"), width: columns.region)
                    downloadedHeaderColumn(String(localized: "Apple 账户"), width: columns.account)
                    Color.clear.frame(width: DownloadedVersionHistoryRow.accountToNoUpdatesGap, height: 1)
                    downloadedHeaderColumn(
                        String(localized: "不再更新"),
                        width: columns.noUpdates + DownloadedVersionHistoryRow.actionGap + DownloadedVersionHistoryRow.actionColumnWidth
                    )
                }
                .padding(.horizontal, DownloadedVersionHistoryRow.rowHorizontalPadding)
                .frame(width: proxy.size.width, height: 30, alignment: .leading)

                ForEach(DownloadedVersionHistoryRow.visualDividerOffsets(for: columns), id: \.self) { x in
                    Rectangle()
                        .fill(Color(nsColor: .separatorColor).opacity(colorScheme == .dark ? 0.62 : 0.52))
                        .frame(width: 1.5, height: 24)
                        .offset(x: x)
                }
            }
        }
        .frame(height: 30)
        .font(.caption.weight(.medium))
        .foregroundStyle(.secondary)
    }

    private func downloadedHeaderColumn(_ title: String, width: CGFloat) -> some View {
        Text(title)
            .lineLimit(1)
            .frame(width: width, alignment: .leading)
    }

    private var downloadCardFill: Color {
        colorScheme == .dark ? Color.white.opacity(0.05) : Color.white.opacity(0.65)
    }

    private var downloadLibraryHeader: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(String(localized: "下载"))
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Text(String(localized: "已下载 App"))
                        .font(.title2.weight(.semibold))
                }
                Spacer()
                if !downloadedItems.isEmpty {
                    Text(String(localized: "\(downloadedAppGroups.count) 个 App · \(downloadedItems.count) 个文件"))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 4)

            SettingsGroupBox {
                HStack(alignment: .center, spacing: 16) {
                    Text(String(localized: "保存目录"))
                        .font(.callout.weight(.medium))

                    Spacer()

                    Text(downloadDir.isEmpty ? String(localized: "未设置") : downloadDir)
                        .font(.callout)
                        .foregroundStyle(downloadDir.isEmpty ? Color.secondary : Color.primary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)

                    Button {
                        chooseDownloadDir()
                    } label: {
                        Label(String(localized: "选择保存目录"), systemImage: "folder")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 12)

                SettingsGroupDivider()

                HStack {
                    Spacer()

                    Button {
                        openDownloadDir()
                    } label: {
                        Label(String(localized: "在访达中显示"), systemImage: "arrow.up.forward.app")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
                    .disabled(downloadDir.isEmpty)
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 12)
            }

            Text(downloadDir.isEmpty
                 ? String(localized: "建议先设置保存目录，再开始下载 IPA。")
                 : String(localized: "IPA 会在此处保存。"))
                .font(.callout)
                .foregroundStyle(.secondary)
                .padding(.top, -4)
        }
    }

    private func downloadedAppCard(_ group: DownloadedAppGroup) -> some View {
        let isMulti = group.items.count > 1
        let isExpanded = expandedGroups.contains(group.id)
        let visibleItems = (isMulti && !isExpanded) ? Array(group.items.prefix(1)) : group.items
        return VStack(spacing: 0) {
            HStack(spacing: 13) {
                Button {
                    searchForApp(group)
                } label: {
                    HStack(spacing: 13) {
                        downloadedAppIcon(path: group.iconPath, size: 50, artworkUrl: group.artworkUrl, isVisionApp: group.isVisionApp)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(group.appName)
                                .font(.headline)
                                .lineLimit(1)
                            Text(group.developer.isEmpty ? group.bundleId : group.developer)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(StablePressButtonStyle())

                Spacer(minLength: 8)

                if isMulti {
                    Button {
                        withAnimation(.snappy(duration: 0.24)) {
                            if isExpanded { expandedGroups.remove(group.id) } else { expandedGroups.insert(group.id) }
                        }
                    } label: {
                        HStack(spacing: 6) {
                            Text(String(localized: "\(group.items.count) 个版本"))
                                .font(.caption.weight(.medium))
                                .foregroundStyle(.secondary)
                            Image(systemName: "chevron.down")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(.secondary)
                                .rotationEffect(.degrees(isExpanded ? 180 : 0))
                        }
                        .padding(.horizontal, 10)
                        .frame(height: 26)
                        .background(.quaternary, in: Capsule())
                        .contentShape(Capsule())
                    }
                    .buttonStyle(StablePressButtonStyle())
                }
            }
            .padding(14)

            ForEach(visibleItems) { item in
                Divider().padding(.leading, 14)
                downloadedVersionRow(item)
            }
        }
        .background(downloadCardFill, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(Color(nsColor: .separatorColor).opacity(0.18), lineWidth: 1)
        }
        .shadow(color: Color.black.opacity(colorScheme == .dark ? 0.30 : 0.07), radius: 9, x: 0, y: 3)
    }

    private func downloadedVersionRow(_ item: DownloadedItem) -> some View {
        HStack(alignment: .center, spacing: 12) {
            downloadedAppIcon(path: item.id, size: 34, artworkUrl: item.artworkUrl, isVisionApp: item.isVisionApp)
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 8) {
                    Text(item.version.isEmpty ? "—" : item.version)
                        .font(.body.weight(.semibold))
                    metaChip(systemImage: "number", text: item.versionId.isEmpty ? "—" : item.versionId, mono: true)
                    metaChip(systemImage: "internaldrive", text: item.sizeText, mono: false)
                }
                HStack(spacing: 14) {
                    let region = appStoreRegion(item.storefrontId)
                    metaLabel(text: region.name)
                    if !item.appleAccount.isEmpty {
                        metaLabel(systemImage: "person.crop.circle", text: item.appleAccount)
                    }
                }
            }
            Spacer(minLength: 8)
            FileActionsBar(
                isSelected: false,
                onReveal: { revealInFinder(item.fileURL) },
                onAirDrop: { airDrop(item.fileURL) },
                onDelete: { deleteDownloaded(item.fileURL) }
            )
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    @ViewBuilder
    private func downloadedAppIcon(path: String, size: CGFloat, artworkUrl: String = "", isVisionApp: Bool = false) -> some View {
        let cornerRadius = isVisionApp ? size * 0.5 : size * 0.25
        Group {
            if let icon = versionIcons[path] {
                Image(nsImage: icon)
                    .resizable()
                    .interpolation(.high)
            } else if !artworkUrl.isEmpty {
                CachedRemoteAppIcon(
                    urlString: artworkUrl,
                    size: size,
                    cornerRadius: cornerRadius,
                    cache: $remoteAppIcons
                )
            } else {
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(.quaternary)
                    .overlay { Image(systemName: "app").foregroundStyle(.secondary) }
            }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .strokeBorder(Color(nsColor: .separatorColor).opacity(0.14), lineWidth: 0.5)
        }
        .shadow(color: appHeaderIconShadow, radius: 4, x: 0, y: 2)
    }

    private func metaChip(systemImage: String, text: String, mono: Bool) -> some View {
        HStack(spacing: 4) {
            Image(systemName: systemImage)
                .font(.system(size: 10, weight: .semibold))
            Text(text)
                .font(mono ? .caption.monospacedDigit() : .caption)
                .textSelection(.enabled)
        }
        .foregroundStyle(.secondary)
        .padding(.horizontal, 8)
        .frame(height: 22)
        .background(.quaternary, in: Capsule())
    }

    private func metaLabel(systemImage: String? = nil, text: String) -> some View {
        HStack(spacing: 5) {
            if let systemImage {
                Image(systemName: systemImage)
                    .font(.caption2)
            }
            Text(text)
                .font(.caption)
                .lineLimit(1)
        }
        .foregroundStyle(.secondary)
    }

    private var logsWorkspace: some View {
        VStack(alignment: .leading, spacing: 18) {
            workspaceHeader(
                eyebrow: String(localized: "运行状态"),
                title: anyRunning ? String(localized: "正在运行") : activeStatus,
                subtitle: String(localized: "下载过程和错误将显示于此处。")
            )

            ScrollViewReader { proxy in
                ScrollView {
                    Text(activeLog.isEmpty ? String(localized: "等待开始。") : activeLog)
                        .font(.body)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(22)

                    Color.clear
                        .frame(height: 1)
                        .id("logEnd")
                }
                .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
                .onChange(of: downloads.focusJob?.log) { _, _ in
                    proxy.scrollTo("logEnd", anchor: .bottom)
                }
            }
        }
    }

    private func workspaceHeader(eyebrow: String, title: String, subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(eyebrow)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.title.weight(.semibold))
                .lineLimit(1)
                .minimumScaleFactor(0.75)
            Text(subtitle)
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
    }

    private func largeEmptyState(systemImage: String, title: String, message: String, fills: Bool = true) -> some View {
        VStack(spacing: 12) {
            Image(systemName: systemImage)
                .font(.system(size: 34, weight: .regular))
                .foregroundStyle(.secondary)
                .frame(width: 48, height: 48)
            Text(title)
                .font(.headline)
                .frame(width: 520)
            Text(message)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)
                .frame(width: 620)
        }
        .frame(maxWidth: .infinity, maxHeight: fills ? .infinity : nil)
    }

    private func sidebarEmptyState(systemImage: String, title: String, message: String) -> some View {
        VStack(spacing: 10) {
            Image(systemName: systemImage)
                .font(.system(size: 28, weight: .regular))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.headline)
            Text(message)
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 20)
        }
    }

    private func selectionPill(title: String, value: String, systemImage: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: systemImage)
            Text(title)
                .foregroundStyle(.secondary)
            Text(value)
                .fontWeight(.semibold)
        }
        .font(.subheadline)
        .padding(.horizontal, 14)
        .frame(height: 38)
        .background(.thinMaterial, in: Capsule())
    }

    private var rightPanelView: some View {
        VStack(spacing: 0) {
            switch rightPanel {
            case .search:
                searchView
            case .versions:
                versionsView
            case .download:
                downloadWorkspace
            case .logs:
                logView
            }
        }
        .background {
            Color(nsColor: .windowBackgroundColor)
                .backgroundExtensionEffect()
        }
    }

    @ViewBuilder
    private var rightPanelPrimaryButton: some View {
        switch rightPanel {
        case .search:
            Button {
                catalog.search()
            } label: {
                Label(String(localized: "搜索"), systemImage: "magnifyingglass")
            }
            .controlSize(.large)
            .buttonStyle(.glass)
            .disabled(catalog.isSearching)
        case .versions:
            Button {
                loadHistoryForActiveApp()
            } label: {
                Label(String(localized: "查询"), systemImage: "clock.arrow.circlepath")
            }
            .controlSize(.large)
            .buttonStyle(.glass)
            .disabled(catalog.isLoadingVersions)
        case .download:
            Button {
                start()
            } label: {
                Label(String(localized: "开始下载"), systemImage: "play.fill")
            }
            .controlSize(.large)
            .buttonStyle(.glassProminent)
            .disabled((selectedDownloadJobID().map { downloads.isRunning($0) } ?? false) || activeAppID.isEmpty || selectedVersion == nil)
        case .logs:
            Button {
                downloads.clearFinished()
            } label: {
                Label(String(localized: "清空"), systemImage: "trash")
            }
            .controlSize(.large)
            .buttonStyle(.glass)
            .disabled(activeLog.isEmpty || anyRunning)
        }
    }

    private var searchView: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                TextField(String(localized: "软件名称、App ID 或 App Store 链接"), text: $catalog.searchQuery)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit {
                        catalog.search()
                    }

                TextField(String(localized: "地区"), text: $catalog.country)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 72)
            }
            .padding(20)

            Divider()

            if catalog.searchResults.isEmpty {
                placeholderView(
                    systemImage: "magnifyingglass",
                    title: catalog.isSearching ? String(localized: "正在搜索") : String(localized: "软件搜索"),
                    message: catalog.searchStatus
                )
            } else {
                VStack(spacing: 0) {
                    searchHeader
                    Divider()
                    List {
                        ForEach(catalog.searchResults) { result in
                            SearchResultRow(result: result)
                                .contentShape(Rectangle())
                                .onTapGesture(count: 2) {
                                    useSearchResult(result, openVersions: true)
                                }
                                .contextMenu {
                                    Button(String(localized: "填入左侧下载")) {
                                        useSearchResult(result, openVersions: false)
                                    }
                                    Button(String(localized: "查询历史版本")) {
                                        useSearchResult(result, openVersions: true)
                                    }
                                    if let url = URL(string: result.trackViewUrl), !result.trackViewUrl.isEmpty {
                                        Button(String(localized: "打开 App Store")) {
                                            NSWorkspace.shared.open(url)
                                        }
                                    }
                                }
                        }
                    }
                }
            }

            Divider()

            HStack {
                Text(catalog.searchStatus)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Spacer()
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
        }
    }

    private var searchHeader: some View {
        HStack(spacing: 12) {
            Text(String(localized: "软件"))
                .frame(maxWidth: .infinity, alignment: .leading)
            Text("App ID")
                .frame(width: 110, alignment: .leading)
            Text("Bundle ID")
                .frame(width: 210, alignment: .leading)
            Text(String(localized: "版本"))
                .frame(width: 90, alignment: .leading)
            Text(String(localized: "大小"))
                .frame(width: 80, alignment: .leading)
        }
        .font(.caption.weight(.medium))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 20)
        .padding(.vertical, 8)
    }

    private var versionsView: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                TextField("App ID", text: $catalog.historyAppID)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit {
                        loadHistoryForActiveApp()
                    }

                Picker(String(localized: "来源"), selection: $catalog.historyProvider) {
                    Text(String(localized: "自动")).tag("auto")
                    Text("Timbrd").tag("timbrd")
                    Text("Agzy").tag("agzy")
                    Text("Bilin").tag("bilin")
                }
                .pickerStyle(.segmented)
                .frame(width: 280)
            }
            .padding(20)

            Divider()

            if versionListLoading {
                centeredSpinner
            } else if catalog.versionResults.isEmpty {
                placeholderView(
                    systemImage: "clock.arrow.circlepath",
                    title: String(localized: "历史版本"),
                    message: catalog.versionStatus
                )
            } else {
                VStack(spacing: 0) {
                    versionsHeader
                    Divider()
                    List {
                        ForEach(catalog.versionResults) { record in
                            VersionResultRow(record: record)
                                .contentShape(Rectangle())
                                .onTapGesture(count: 2) {
                                    useVersion(record)
                                }
                                .contextMenu {
                                    Button(String(localized: "填入下载")) {
                                        useVersion(record)
                                    }
                                }
                        }
                    }
                }
            }

            Divider()

            HStack {
                Text(catalog.versionStatus)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Spacer()
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
        }
        .onAppear {
            if catalog.historyAppID.isEmpty {
                catalog.historyAppID = downloadAppID
            }
        }
    }

    private var versionsHeader: some View {
        GeometryReader { proxy in
            let columns = VersionSelectionRow.columns(for: proxy.size.width)

            ZStack(alignment: .leading) {
                HStack(spacing: 0) {
                    Color.clear
                        .frame(width: VersionSelectionRow.iconColumnWidth, height: 1)
                    versionHeaderColumn(String(localized: "版本号"), width: columns.version)
                    versionHeaderColumn(String(localized: "版本 ID"), width: columns.versionID)
                    versionHeaderColumn(String(localized: "大小"), width: columns.size)
                    HStack(spacing: 0) {
                        Color.clear
                            .frame(width: VersionSelectionRow.noUpdatesHeaderInset(for: columns), height: 1)
                        Text(String(localized: "不再更新"))
                            .lineLimit(1)
                            .minimumScaleFactor(0.82)
                        Spacer(minLength: 0)
                    }
                    .frame(
                        width: columns.noUpdates + VersionSelectionRow.actionGap + VersionSelectionRow.actionColumnWidth,
                        alignment: .leading
                    )
                }
                .padding(.horizontal, VersionSelectionRow.rowHorizontalPadding)
                .frame(width: proxy.size.width, height: 30, alignment: .leading)

                ForEach(VersionSelectionRow.visualDividerOffsets(for: columns), id: \.self) { x in
                    Rectangle()
                        .fill(Color(nsColor: .separatorColor).opacity(colorScheme == .dark ? 0.62 : 0.52))
                        .frame(width: 1.5, height: 25)
                        .offset(x: x)
                }
            }
        }
        .frame(height: 30)
        .font(.caption.weight(.medium))
        .foregroundStyle(.secondary)
    }

    private func versionHeaderColumn(_ title: String, width: CGFloat) -> some View {
        Text(title)
            .frame(width: width, alignment: .leading)
    }

    private var versionsHeaderBar: some View {
        VStack(spacing: 0) {
            versionsHeader
                .frame(maxWidth: .infinity, alignment: .leading)

            Divider()
        }
        .background(.windowBackground)
    }

    private var versionsFooterBar: some View {
        VStack(spacing: 0) {
            Divider()

            versionListStatusBar
        }
        .background(.windowBackground)
    }

    private var versionListStatusBar: some View {
        ZStack {
            Text(String(localized: "搜索到 \(catalog.versionResults.count) 个版本，来源 \(versionResultSourceSummary)"))
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity)
        .frame(height: 32, alignment: .center)
    }

    private var versionResultSourceSummary: String {
        let sources = Array(Set(catalog.versionResults.map(\.source).filter { !$0.isEmpty })).sorted()
        if sources.count == 1, let source = sources.first {
            return source
        }
        return providerDisplayName(catalog.historyProvider)
    }

    private func providerDisplayName(_ provider: String) -> String {
        switch provider {
        case "auto":
            return String(localized: "自动")
        case "timbrd":
            return "Timbrd"
        case "agzy":
            return "Agzy"
        case "bilin":
            return "Bilin"
        case "apple":
            return "Apple"
        default:
            return provider
        }
    }

    private var logView: some View {
        VStack(spacing: 0) {
            HStack {
                Label(anyRunning ? String(localized: "正在运行") : activeStatus, systemImage: anyRunning ? "bolt.fill" : "circle.fill")
                    .font(.subheadline.weight(.medium))
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 12)

            Divider()

            ScrollViewReader { proxy in
                ScrollView {
                    Text(activeLog.isEmpty ? String(localized: "等待开始。") : activeLog)
                        .font(.body)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(24)

                    Color.clear
                        .frame(height: 1)
                        .id("logEnd")
                }
                .onChange(of: downloads.focusJob?.log) { _, _ in
                    proxy.scrollTo("logEnd", anchor: .bottom)
                }
            }
        }
    }

    private func placeholderView(systemImage: String, title: String, message: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: systemImage)
                .font(.system(size: 36))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.title3.weight(.semibold))
            Text(message)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var sidebarDirectoryField: some View {
        VStack(alignment: .leading, spacing: 8) {
            sidebarFieldLabel(String(localized: "目录"), systemImage: "folder")
            HStack(spacing: 8) {
                TextField("", text: $downloadDir, prompt: Text(String(localized: "选择下载保存目录")))
                    .textFieldStyle(.roundedBorder)
                    .font(.body)
                    .controlSize(.large)
                    .lineLimit(1)

                Button {
                    chooseDownloadDir()
                } label: {
                    Image(systemName: "folder")
                }
                .controlSize(.large)
                .buttonStyle(.bordered)
                .buttonBorderShape(.capsule)
            }
        }
        .padding(.vertical, 2)
    }

    private func sidebarTextField(_ label: String, text: Binding<String>, prompt: String, systemImage: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            sidebarFieldLabel(label, systemImage: systemImage)
            TextField("", text: text, prompt: Text(prompt))
                .textFieldStyle(.roundedBorder)
                .font(.body)
                .controlSize(.large)
                .lineLimit(1)
        }
        .padding(.vertical, 2)
    }

    private func sidebarSecureField(_ label: String, text: Binding<String>, prompt: String, systemImage: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            sidebarFieldLabel(label, systemImage: systemImage)
            SecureField("", text: text, prompt: Text(prompt))
                .textFieldStyle(.roundedBorder)
                .font(.body)
                .controlSize(.large)
                .lineLimit(1)
        }
        .padding(.vertical, 2)
    }

    private func sidebarFieldLabel(_ text: String, systemImage: String) -> some View {
        Label(text, systemImage: systemImage)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(.secondary)
    }

    private func loadSavedValuesOnce() {
        guard !didLoadCredentials else { return }
        didLoadCredentials = true

        if downloadDir.isEmpty {
            downloadDir = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first?.path ?? NSHomeDirectory()
        }

        downloadAppID = ""
        downloadVersionID = ""
        manualAppID = ""
        manualVersionID = ""
        manualNoUpdate = false
        catalog.historyAppID = ""
        catalog.platform = AppSearchPlatform.named(selectedSearchPlatformID).rawValue
        if AppSearchPlatform.named(selectedSearchPlatformID) == .vision {
            catalog.historyProvider = "apple"
        }

        accountStore.load()
        let initialCountry = accountStore.selectedAccount?.countryCode ?? selectedCountryCode
        applyStorefrontCountry(initialCountry, reload: false)

        if catalog.searchResults.isEmpty && catalog.searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            catalog.loadFeatured()
        }

        DispatchQueue.main.async {
            activeField = nil
            NSApp.keyWindow?.makeFirstResponder(nil)
        }
    }

    private var selectedSearchPlatform: AppSearchPlatform {
        AppSearchPlatform.named(selectedSearchPlatformID)
    }

    private var activeAppIsVision: Bool {
        selectedApp?.isVisionApp == true
    }

    private var visionHistoryNeedsAppleSource: Bool {
        activeAppIsVision && catalog.historyProvider != "apple" && !activeAppID.isEmpty
    }

    private func selectSearchPlatform(_ platform: AppSearchPlatform) {
        guard selectedSearchPlatform != platform else { return }
        selectedSearchPlatformID = platform.rawValue
        catalog.platform = platform.rawValue
        clearActiveAppSelectionForPlatformChange()
        if platform == .vision {
            catalog.historyProvider = "apple"
        } else if catalog.historyProvider == "apple" {
            catalog.historyProvider = "auto"
        }
        activeField = nil
        NSApp.keyWindow?.makeFirstResponder(nil)

        if catalog.searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            catalog.loadFeatured()
        } else {
            catalog.search()
        }
    }

    private func clearActiveAppSelectionForPlatformChange() {
        selectedApp = nil
        selectedAppLocalIconPath = nil
        selectedVersion = nil
        selectedVersionIDs.removeAll()
        lastSelectedVersionID = nil
        appleVersionFetchNeedsAcquisition = false
        downloadAppID = ""
        downloadVersionID = ""
        manualAppID = ""
        manualVersionID = ""
        manualNoUpdate = false
        catalog.historyAppID = ""
        catalog.selectedSearchID = nil
        catalog.selectedVersionID = nil
        catalog.searchResults = []
        catalog.versionResults = []
        catalog.versionStatus = String(localized: "输入 App ID 以查询历史版本。")
    }

    private func applyStorefrontCountry(_ code: String, reload: Bool) {
        let country = AppStoreCountry.named(code)
        selectedCountryCode = country.code
        catalog.country = country.code

        guard reload, rightPanel == .search else { return }
        if catalog.searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            catalog.loadFeatured()
        } else {
            catalog.search()
        }
    }

    private func prepareSearchFromDownload() {
        let cleanAppID = downloadAppID.trimmingCharacters(in: .whitespacesAndNewlines)
        catalog.searchQuery = cleanAppID.isEmpty ? catalog.searchQuery : cleanAppID
        rightPanel = .search
        catalog.search()
    }

    private func searchForApp(_ group: DownloadedAppGroup) {
        let query = group.appId.isEmpty ? group.appName : group.appId
        guard !query.isEmpty else { return }
        if group.isVisionApp {
            selectedSearchPlatformID = AppSearchPlatform.vision.rawValue
            catalog.platform = AppSearchPlatform.vision.rawValue
            catalog.historyProvider = "apple"
        }
        if let code = storefrontCountryCode(group.storefrontId) {
            selectedCountryCode = code
            catalog.country = code
        }
        catalog.searchQuery = query
        rightPanel = .search
        catalog.search()
    }

    private func prepareVersionsFromDownload() {
        catalog.historyAppID = downloadAppID.trimmingCharacters(in: .whitespacesAndNewlines)
        selectedVersion = nil
        selectedVersionIDs.removeAll()
        lastSelectedVersionID = nil
        rightPanel = .search
        loadHistoryForActiveApp()
    }

    private func selectApp(_ result: AppSearchResult) {
        selectedApp = result
        selectedAppLocalIconPath = nil
        selectedVersion = nil
        selectedVersionIDs.removeAll()
        lastSelectedVersionID = nil
        appleVersionFetchNeedsAcquisition = false
        downloadAppID = result.id
        downloadVersionID = ""
        manualAppID = result.id
        manualVersionID = ""
        manualNoUpdate = false
        catalog.historyAppID = result.id
        rightPanel = .search
        if result.isVisionApp || selectedSearchPlatform == .vision {
            selectedSearchPlatformID = AppSearchPlatform.vision.rawValue
            catalog.platform = AppSearchPlatform.vision.rawValue
            catalog.historyProvider = "apple"
        }
        loadHistoryForActiveApp()
    }

    private func selectVersion(_ record: VersionRecord, updateSelection: Bool = true) {
        if updateSelection {
            selectedVersionIDs = [record.id]
        }
        lastSelectedVersionID = record.id
        selectedVersion = record
        downloadVersionID = record.versionId
        manualAppID = activeAppID
        catalog.selectedVersionID = record.id
        catalog.versionStatus = String(localized: "已选择 \(record.version)，版本 ID：\(record.versionId)。")
    }

    private func handleVersionRowSelection(_ record: VersionRecord) {
        activeField = nil
        KeyboardShortcutState.shared.isTextEditing = false
        let modifiers = NSEvent.modifierFlags.intersection(.deviceIndependentFlagsMask)
        let commandPressed = modifiers.contains(.command)
        let shiftPressed = modifiers.contains(.shift)

        if shiftPressed,
           let anchorID = lastSelectedVersionID,
           let anchorIndex = catalog.versionResults.firstIndex(where: { $0.id == anchorID }),
           let targetIndex = catalog.versionResults.firstIndex(where: { $0.id == record.id }) {
            let bounds = min(anchorIndex, targetIndex)...max(anchorIndex, targetIndex)
            let rangeIDs = Set(catalog.versionResults[bounds].map(\.id))
            selectedVersionIDs = commandPressed ? selectedVersionIDs.union(rangeIDs) : rangeIDs
            selectVersion(record, updateSelection: false)
            return
        }

        if commandPressed {
            if selectedVersionIDs.contains(record.id) {
                selectedVersionIDs.remove(record.id)
                if selectedVersion?.id == record.id {
                    selectFallbackVersionAfterDeselection()
                }
            } else {
                selectedVersionIDs.insert(record.id)
                selectVersion(record, updateSelection: false)
            }
        } else {
            selectVersion(record)
        }
    }

    private func selectFallbackVersionAfterDeselection() {
        guard let fallback = catalog.versionResults.first(where: { selectedVersionIDs.contains($0.id) }) else {
            selectedVersion = nil
            downloadVersionID = ""
            catalog.selectedVersionID = nil
            lastSelectedVersionID = nil
            return
        }
        selectVersion(fallback, updateSelection: false)
    }

    private func downloadVersion(_ record: VersionRecord, preserveSelection: Bool = false) {
        selectVersion(record, updateSelection: !preserveSelection)
        start()
    }

    private func downloadSelectedVersions() {
        let records = catalog.versionResults.filter { selectedVersionIDs.contains($0.id) }
        guard !records.isEmpty else { return }
        for record in records {
            let removesUpdates = noUpdateEnabled(for: record)
            let jobID = downloadJobID(for: record, removesAppStoreUpdates: removesUpdates)
            guard !downloads.isRunning(jobID) else { continue }
            guard downloadedFileFor(record, removesAppStoreUpdates: removesUpdates) == nil else { continue }
            downloadVersion(record, preserveSelection: true)
        }
    }

    private func showsBatchDownloadMenu(for record: VersionRecord) -> Bool {
        selectedVersionIDs.count > 1 && selectedVersionIDs.contains(record.id)
    }

    private func handleSelectAllShortcut() {
        switch rightPanel {
        case .search, .versions:
            selectAllVersionRows()
        case .download:
            switch downloadSelectionScope {
            case .appGroups:
                selectAllDownloadedGroupRows()
            case .versions:
                selectAllDownloadedRows()
            }
        case .logs:
            break
        }
    }

    private func handleRefreshShortcut() {
        switch rightPanel {
        case .download:
            refreshDownloadedFiles()
        case .search, .versions:
            if !activeAppID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                loadHistoryForActiveApp()
            } else if catalog.searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                catalog.loadFeatured()
            } else {
                catalog.search()
            }
        case .logs:
            break
        }
    }

    private func selectAllVersionRows() {
        guard !catalog.versionResults.isEmpty else { return }
        selectedVersionIDs = Set(catalog.versionResults.map(\.id))
        if let first = catalog.versionResults.first {
            selectVersion(first, updateSelection: false)
        }
    }

    private func selectAllDownloadedRows() {
        guard let group = selectedDownloadedGroup, !group.items.isEmpty else { return }
        downloadSelectionScope = .versions
        selectedDownloadedItemIDs = Set(group.items.map(\.id))
        selectedDownloadedItemID = group.items.first?.id
        lastSelectedDownloadedItemID = selectedDownloadedItemID
    }

    private func selectAllDownloadedGroupRows() {
        guard !filteredDownloadedAppGroups.isEmpty else { return }
        downloadSelectionScope = .appGroups
        selectedDownloadedGroupIDs = Set(filteredDownloadedAppGroups.map(\.id))
        if let first = filteredDownloadedAppGroups.first {
            selectedDownloadedGroupID = first.id
            lastSelectedDownloadedGroupID = first.id
        }
        selectedDownloadedItemID = nil
        selectedDownloadedItemIDs.removeAll()
        lastSelectedDownloadedItemID = nil
    }

    private func handleDownloadedGroupSelection(_ group: DownloadedAppGroup) {
        activeField = nil
        KeyboardShortcutState.shared.isTextEditing = false
        downloadSelectionScope = .appGroups
        selectedDownloadedItemID = nil
        selectedDownloadedItemIDs.removeAll()
        lastSelectedDownloadedItemID = nil
        if !group.appId.isEmpty {
            manualAppID = group.appId
            manualVersionID = ""
            manualLatestDownloadedPath = nil
            manualLatestDownloadedJobID = nil
        }

        let modifiers = NSEvent.modifierFlags.intersection(.deviceIndependentFlagsMask)
        let commandPressed = modifiers.contains(.command)
        let shiftPressed = modifiers.contains(.shift)

        if shiftPressed,
           let anchorID = lastSelectedDownloadedGroupID,
           let anchorIndex = filteredDownloadedAppGroups.firstIndex(where: { $0.id == anchorID }),
           let targetIndex = filteredDownloadedAppGroups.firstIndex(where: { $0.id == group.id }) {
            let bounds = min(anchorIndex, targetIndex)...max(anchorIndex, targetIndex)
            let rangeIDs = Set(filteredDownloadedAppGroups[bounds].map(\.id))
            selectedDownloadedGroupIDs = commandPressed ? selectedDownloadedGroupIDs.union(rangeIDs) : rangeIDs
            selectedDownloadedGroupID = group.id
            return
        }

        if commandPressed {
            if selectedDownloadedGroupIDs.contains(group.id) {
                selectedDownloadedGroupIDs.remove(group.id)
                if selectedDownloadedGroupID == group.id {
                    selectedDownloadedGroupID = firstSelectedDownloadedGroupID()
                }
                if selectedDownloadedGroupIDs.isEmpty {
                    selectedDownloadedGroupID = nil
                    lastSelectedDownloadedGroupID = nil
                }
            } else {
                selectedDownloadedGroupIDs.insert(group.id)
                selectedDownloadedGroupID = group.id
                lastSelectedDownloadedGroupID = group.id
            }
        } else {
            selectedDownloadedGroupIDs = [group.id]
            selectedDownloadedGroupID = group.id
            lastSelectedDownloadedGroupID = group.id
        }
    }

    private func handleDownloadedRowSelection(_ item: DownloadedItem) {
        activeField = nil
        KeyboardShortcutState.shared.isTextEditing = false
        downloadSelectionScope = .versions
        let modifiers = NSEvent.modifierFlags.intersection(.deviceIndependentFlagsMask)
        let commandPressed = modifiers.contains(.command)
        let shiftPressed = modifiers.contains(.shift)

        if shiftPressed,
           let anchorID = lastSelectedDownloadedItemID,
           let items = selectedDownloadedGroup?.items,
           let anchorIndex = items.firstIndex(where: { $0.id == anchorID }),
           let targetIndex = items.firstIndex(where: { $0.id == item.id }) {
            let bounds = min(anchorIndex, targetIndex)...max(anchorIndex, targetIndex)
            let rangeIDs = Set(items[bounds].map(\.id))
            selectedDownloadedItemIDs = commandPressed ? selectedDownloadedItemIDs.union(rangeIDs) : rangeIDs
            selectedDownloadedItemID = item.id
            return
        }

        if commandPressed {
            if selectedDownloadedItemIDs.contains(item.id) {
                selectedDownloadedItemIDs.remove(item.id)
                if selectedDownloadedItemID == item.id {
                    selectedDownloadedItemID = selectedDownloadedItemIDs.first
                }
            } else {
                selectedDownloadedItemIDs.insert(item.id)
                selectedDownloadedItemID = item.id
                lastSelectedDownloadedItemID = item.id
            }
        } else {
            selectedDownloadedItemIDs = [item.id]
            selectedDownloadedItemID = item.id
            lastSelectedDownloadedItemID = item.id
        }
    }

    private func showsBatchDeleteMenu(for item: DownloadedItem) -> Bool {
        selectedDownloadedItemIDs.count > 1 && selectedDownloadedItemIDs.contains(item.id)
    }

    private func showsBatchDeleteMenu(for group: DownloadedAppGroup) -> Bool {
        selectedDownloadedGroupIDs.count > 1 && selectedDownloadedGroupIDs.contains(group.id)
    }

    private func deleteSelectedDownloadedItems() {
        guard !selectedDownloadedItemIDs.isEmpty else { return }
        let urls = downloadedItems
            .filter { selectedDownloadedItemIDs.contains($0.id) }
            .map(\.fileURL)

        for url in urls {
            try? FileManager.default.trashItem(at: url, resultingItemURL: nil)
        }
        selectedDownloadedItemIDs.removeAll()
        selectedDownloadedItemID = nil
        lastSelectedDownloadedItemID = nil
        refreshDownloadedFiles()
    }

    private func deleteDownloadedGroup(_ group: DownloadedAppGroup) {
        deleteDownloadedGroups(withIDs: [group.id])
    }

    private func deleteSelectedDownloadedGroups() {
        guard !selectedDownloadedGroupIDs.isEmpty else { return }
        deleteDownloadedGroups(withIDs: selectedDownloadedGroupIDs)
    }

    private func deleteDownloadedGroups(withIDs groupIDs: Set<String>) {
        guard !groupIDs.isEmpty else { return }
        let fallbackGroupID = filteredDownloadedAppGroups.first { !groupIDs.contains($0.id) }?.id
        let urls = downloadedItems
            .filter { groupIDs.contains($0.groupKey) }
            .map(\.fileURL)

        for url in urls {
            try? FileManager.default.trashItem(at: url, resultingItemURL: nil)
        }

        selectedDownloadedGroupIDs.subtract(groupIDs)
        if selectedDownloadedGroupIDs.isEmpty, let fallbackGroupID {
            selectedDownloadedGroupIDs = [fallbackGroupID]
            selectedDownloadedGroupID = fallbackGroupID
            lastSelectedDownloadedGroupID = fallbackGroupID
        } else if let selectedDownloadedGroupID, groupIDs.contains(selectedDownloadedGroupID) {
            self.selectedDownloadedGroupID = firstSelectedDownloadedGroupID()
        }
        if let lastSelectedDownloadedGroupID, groupIDs.contains(lastSelectedDownloadedGroupID) {
            self.lastSelectedDownloadedGroupID = firstSelectedDownloadedGroupID()
        }
        selectedDownloadedItemID = nil
        selectedDownloadedItemIDs.removeAll()
        lastSelectedDownloadedItemID = nil
        downloadSelectionScope = .appGroups
        refreshDownloadedFiles()
    }

    private static let versionIDsFetchJobKey = "__ipa_versionids_fetch__"

    private static func filenameVersionAndVariant(from stem: String) -> (name: String, version: String, variant: IPADownloadVariant) {
        let suffix = "_no-update"
        let variant: IPADownloadVariant
        let baseStem: String
        if stem.localizedCaseInsensitiveContains(suffix), stem.lowercased().hasSuffix(suffix) {
            variant = .noUpdates
            baseStem = String(stem.dropLast(suffix.count))
        } else {
            variant = .original
            baseStem = stem
        }

        guard let underscore = baseStem.lastIndex(of: "_") else {
            return (baseStem, "", variant)
        }

        let name = String(baseStem[..<underscore])
        let version = String(baseStem[baseStem.index(after: underscore)...])
        return (name, version, variant)
    }

    private func fetchVersionIDsFromApple(allowAppAcquisition: Bool = false) {
        guard let account = accountStore.selectedAccount else {
            saveMessage = String(localized: "请先登录 Apple 账户。")
            showSettings()
            return
        }
        let acct = account.appleAccount.trimmingCharacters(in: .whitespacesAndNewlines)
        let pwd: String
        do {
            pwd = try accountStore.password(for: account)
        } catch {
            saveMessage = error.localizedDescription
            return
        }
        let appID = activeAppID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !acct.isEmpty, !pwd.isEmpty else {
            saveMessage = String(localized: "请先登录 Apple 账户。"); showSettings(); return
        }
        guard !appID.isEmpty else { return }
        selectedVersion = nil
        selectedVersionIDs.removeAll()
        lastSelectedVersionID = nil
        catalog.selectedVersionID = nil
        catalog.versionResults = []
        appleVersionFetchNeedsAcquisition = false
        catalog.versionStatus = String(localized: "正在从 Apple 获取版本…")
        let config = RunConfig(appleAccount: acct, password: pwd, code: "",
                               appID: appID, versionID: "", downloadDir: "", listVersionIDs: true,
                               appIsFree: appIsFreeFlag(), appCountry: selectedCountryCode,
                               allowAppAcquisition: allowAppAcquisition)
        downloads.start(id: Self.versionIDsFetchJobKey, label: String(localized: "获取版本列表"), config: config)
    }

    private func appIsFreeFlag() -> String {
        guard let app = selectedApp, app.id == activeAppID else { return "" }
        let price = app.price.trimmingCharacters(in: .whitespacesAndNewlines)
        if price.isEmpty { return "" }
        return price.contains(where: { $0.isNumber }) ? "0" : "1"
    }

    private func downloadManualVersionID() {
        let appID = manualAppIDTrimmed
        let vid = manualVersionIDTrimmed
        guard !appID.isEmpty else { return }
        let variant = manualDownloadVariant
        let jobID = manualDownloadJobID
        let startedAt = Date()
        selectedVersion = nil
        selectedVersionIDs.removeAll()
        lastSelectedVersionID = nil
        if selectedApp?.id != appID {
            selectedApp = nil
            selectedAppLocalIconPath = nil
        }
        downloadAppID = appID
        downloadVersionID = vid
        catalog.historyAppID = appID
        catalog.selectedVersionID = nil
        if vid.isEmpty {
            manualLatestDownloadedPath = nil
            manualLatestDownloadedJobID = jobID
        }
        start(removeAppStoreUpdateMetadataOverride: manualNoUpdate)
        if vid.isEmpty {
            trackManualLatestDownload(jobID: jobID, appID: appID, variant: variant, startedAt: startedAt)
        }
    }

    private func trackManualLatestDownload(jobID: String, appID: String, variant: IPADownloadVariant, startedAt: Date) {
        Task { @MainActor in
            for _ in 0..<1800 {
                guard manualLatestDownloadedJobID == jobID else { return }
                guard let job = downloads.job(jobID) else {
                    try? await Task.sleep(nanoseconds: 200_000_000)
                    continue
                }

                if job.status == .failed {
                    return
                }

                if job.status == .done {
                    for _ in 0..<30 {
                        refreshDownloadedFiles()
                        if let url = newestDownloadedURL(appID: appID, variant: variant, after: startedAt) {
                            manualLatestDownloadedPath = url.path
                            return
                        }
                        try? await Task.sleep(nanoseconds: 180_000_000)
                    }
                    return
                }

                try? await Task.sleep(nanoseconds: 200_000_000)
            }
        }
    }

    private func parseFetchedVersionIDs(from log: String) {
        let lines = log.split(separator: "\n").map(String.init)
        guard let line = lines.first(where: { $0.contains("\"versionIds\"") }),
              let data = line.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ids = obj["versionIds"] as? [String] else {
            catalog.versionResults = []
            selectedVersionIDs.removeAll()
            lastSelectedVersionID = nil
            if let errorLine = lines.last(where: { $0.contains("[X]") }) {
                catalog.versionStatus = cleanDownloadErrorDetail(errorLine)
                    ?? String(localized: "未能从 Apple 获取版本，请改用其他来源。")
            } else {
                catalog.versionStatus = String(localized: "未能从 Apple 获取版本，请改用其他来源。")
            }
            return
        }
        if (obj["requiresAcquisition"] as? Bool) == true {
            catalog.versionResults = []
            selectedVersionIDs.removeAll()
            lastSelectedVersionID = nil
            appleVersionFetchNeedsAcquisition = true
            catalog.versionStatus = String(localized: "此 Apple 账户未拥有此 App，是否从 Apple 获取此 App？")
            return
        }
        let records = ids.reversed().map { id in
            VersionRecord(id: "apple-\(id)", version: "—", versionId: id, date: "", size: "", source: "Apple")
        }
        appleVersionFetchNeedsAcquisition = false
        selectedVersionIDs.removeAll()
        lastSelectedVersionID = nil
        catalog.versionResults = records
        catalog.versionStatus = String(localized: "已从 Apple 元数据获取 \(records.count) 个版本 ID。")
    }

    private func refreshDownloadedFiles() {
        let dirPath = downloadDir.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !dirPath.isEmpty else { downloadedFiles = [:]; return }
        let dirURL = URL(fileURLWithPath: (dirPath as NSString).expandingTildeInPath, isDirectory: true)
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(at: dirURL, includingPropertiesForKeys: [.isRegularFileKey]) else {
            downloadedFiles = [:]
            return
        }
        var map: [String: URL] = [:]
        for url in items where url.pathExtension.lowercased() == "ipa" {
            let stem = url.deletingPathExtension().lastPathComponent
            let parsed = Self.filenameVersionAndVariant(from: stem)
            if !parsed.version.isEmpty {
                map[downloadedFileKey(parsed.version, variant: parsed.variant)] = url
            }
        }
        downloadedFiles = map
        let livePaths = Set(map.values.map { $0.path })
        versionIcons = versionIcons.filter { livePaths.contains($0.key) }
        downloadedVersionIDs = downloadedVersionIDs.filter { livePaths.contains($0.value.path) }
        for url in map.values where versionIcons[url.path] == nil {
            loadAppIcon(from: url)
        }
        refreshDownloadLibrary()
    }

    private func refreshDownloadLibrary() {
        let dirPath = downloadDir.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !dirPath.isEmpty else { downloadedItems = []; return }
        let dirURL = URL(fileURLWithPath: (dirPath as NSString).expandingTildeInPath, isDirectory: true)
        let fm = FileManager.default
        guard let urls = try? fm.contentsOfDirectory(at: dirURL, includingPropertiesForKeys: [.fileSizeKey, .creationDateKey, .contentModificationDateKey]) else {
            downloadedItems = []
            return
        }
        let ipaURLs = urls.filter { $0.pathExtension.lowercased() == "ipa" }

        for url in ipaURLs where versionIcons[url.path] == nil {
            loadAppIcon(from: url)
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let extracted = ipaURLs.compactMap { Self.extractDownloadedItem(fromIPA: $0) }
            DispatchQueue.main.async {
                downloadedItems = extracted
                let validDownloadedIDs = Set(extracted.map(\.id))
                let validDownloadedGroupIDs = Set(extracted.map(\.groupKey))
                selectedDownloadedItemIDs.formIntersection(validDownloadedIDs)
                selectedDownloadedGroupIDs.formIntersection(validDownloadedGroupIDs)
                if let selectedDownloadedItemID,
                   !extracted.contains(where: { $0.id == selectedDownloadedItemID }) {
                    self.selectedDownloadedItemID = nil
                }
                if let lastSelectedDownloadedGroupID,
                   !validDownloadedGroupIDs.contains(lastSelectedDownloadedGroupID) {
                    self.lastSelectedDownloadedGroupID = nil
                }
                if let selectedDownloadedGroupID,
                   !validDownloadedGroupIDs.contains(selectedDownloadedGroupID) {
                    self.selectedDownloadedGroupID = self.firstSelectedDownloadedGroupID()
                    selectedDownloadedItemIDs.removeAll()
                    lastSelectedDownloadedItemID = nil
                }
            }
        }
    }

    private static func extractDownloadedItem(fromIPA url: URL) -> DownloadedItem? {
        let path = url.path
        let attrs = try? FileManager.default.attributesOfItem(atPath: path)
        let size = (attrs?[.size] as? NSNumber)?.int64Value ?? 0
        let date = (attrs?[.creationDate] as? Date) ?? (attrs?[.modificationDate] as? Date) ?? Date()
        let stem = url.deletingPathExtension().lastPathComponent
        let filenameInfo = filenameVersionAndVariant(from: stem)

        let metadataInfo = downloadedMetadata(fromIPA: path)
        guard let data = metadataInfo.data,
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
        else {
            let name = filenameInfo.name.isEmpty ? stem : filenameInfo.name
            return DownloadedItem(id: path, fileURL: url, appName: name, developer: "", bundleId: "",
                                  appId: "", groupKey: name, version: filenameInfo.version, versionId: "", sizeBytes: size,
                                  appleAccount: "", storefrontId: "", downloadDate: date,
                                  removesAppStoreUpdates: filenameInfo.variant.removesAppStoreUpdates,
                                  artworkUrl: "", softwarePlatform: "")
        }

        func str(_ key: String) -> String {
            if let s = plist[key] as? String { return s }
            if let n = plist[key] as? NSNumber { return n.stringValue }
            return ""
        }
        let appName = !str("itemName").isEmpty ? str("itemName")
            : (!str("bundleDisplayName").isEmpty ? str("bundleDisplayName") : stem)
        let itemId = str("itemId")
        let bundleId = str("softwareVersionBundleId")
        let groupKey = !itemId.isEmpty ? itemId : (!bundleId.isEmpty ? bundleId : appName)
        let version = !str("bundleShortVersionString").isEmpty ? str("bundleShortVersionString") : filenameInfo.version

        return DownloadedItem(
            id: path,
            fileURL: url,
            appName: appName,
            developer: str("artistName"),
            bundleId: bundleId,
            appId: itemId,
            groupKey: groupKey,
            version: version,
            versionId: str("softwareVersionExternalIdentifier"),
            sizeBytes: size,
            appleAccount: str("appleId"),
            storefrontId: str("s"),
            downloadDate: date,
            removesAppStoreUpdates: metadataInfo.removesAppStoreUpdates || filenameInfo.variant.removesAppStoreUpdates,
            artworkUrl: str("softwareIcon57x57URL"),
            softwarePlatform: str("software-platform")
        )
    }

    private var downloadedAppGroups: [DownloadedAppGroup] {
        let grouped = Dictionary(grouping: downloadedItems) { $0.groupKey }
        return grouped.map { key, items in
            DownloadedAppGroup(id: key, items: items.sorted { $0.downloadDate > $1.downloadDate })
        }
        .sorted { ($0.items.first?.downloadDate ?? .distantPast) > ($1.items.first?.downloadDate ?? .distantPast) }
    }

    private var filteredDownloadedAppGroups: [DownloadedAppGroup] {
        let query = downloadSearchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return downloadedAppGroups }

        return downloadedAppGroups.filter { group in
            let groupFields = [
                group.appName,
                group.developer,
                group.bundleId,
                group.appId
            ]

            if groupFields.contains(where: { $0.localizedCaseInsensitiveContains(query) }) {
                return true
            }

            return group.items.contains { item in
                [
                    item.version,
                    item.versionId,
                    item.appleAccount,
                    item.sizeText,
                    item.dateText,
                    appStoreRegion(item.storefrontId).name
                ].contains { $0.localizedCaseInsensitiveContains(query) }
            }
        }
    }

    private var downloadedColumns: [[DownloadedAppGroup]] {
        let groups = downloadedAppGroups
        var cols: [[DownloadedAppGroup]] = [[], []]
        for (index, group) in groups.enumerated() {
            cols[index % 2].append(group)
        }
        return cols
    }

    private func loadAppIcon(from ipaURL: URL) {
        let path = ipaURL.path
        DispatchQueue.global(qos: .utility).async {
            let image = Self.extractAppIcon(fromIPA: path)
            let metadata = Self.extractVersionMetadata(fromIPA: path)
            DispatchQueue.main.async {
                if let image { versionIcons[path] = image }
                if let versionID = metadata.versionID {
                    downloadedVersionIDs[downloadedFileKey(versionID, variant: metadata.variant)] = ipaURL
                }
            }
        }
    }

    private static func extractVersionMetadata(fromIPA path: String) -> (versionID: String?, variant: IPADownloadVariant) {
        let metadataInfo = downloadedMetadata(fromIPA: path)
        guard let data = metadataInfo.data,
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
        else { return (nil, .original) }
        let variant = IPADownloadVariant(removeAppStoreUpdateMetadata: metadataInfo.removesAppStoreUpdates)
        if let n = plist["softwareVersionExternalIdentifier"] as? NSNumber { return (n.stringValue, variant) }
        if let s = plist["softwareVersionExternalIdentifier"] as? String { return (s, variant) }
        return (nil, variant)
    }

    private func downloadedFileFor(_ record: VersionRecord, removesAppStoreUpdates: Bool) -> URL? {
        let appID = activeAppID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !appID.isEmpty else { return nil }
        return downloadedItems.first { item in
            guard item.appId == appID,
                  item.removesAppStoreUpdates == removesAppStoreUpdates else {
                return false
            }

            if !record.versionId.isEmpty {
                return item.versionId == record.versionId
            }

            return !record.version.isEmpty && item.version == record.version
        }?.fileURL
    }

    private func newestDownloadedURL(appID: String, variant: IPADownloadVariant, after startedAt: Date) -> URL? {
        downloadedItems
            .filter { item in
                item.appId == appID
                    && item.removesAppStoreUpdates == variant.removesAppStoreUpdates
                    && item.downloadDate >= startedAt.addingTimeInterval(-2)
            }
            .sorted { $0.downloadDate > $1.downloadDate }
            .first?
            .fileURL
    }

    private static func runUnzip(_ args: [String]) -> Data? {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice
        do { try proc.run() } catch { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return data.isEmpty ? nil : data
    }

    private static func downloadedMetadata(fromIPA path: String) -> (data: Data?, removesAppStoreUpdates: Bool) {
        if let data = runUnzip(["-p", path, "iTunesMetadata.plist"]) {
            return (data, false)
        }
        if let data = runUnzip(["-p", path, "PastelMetadata.plist"]) {
            return (data, true)
        }
        return (nil, false)
    }

    private static func extractAppIcon(fromIPA path: String) -> NSImage? {
        guard let listData = runUnzip(["-Z1", path]),
              let list = String(data: listData, encoding: .utf8) else { return nil }
        let entries = list.split(separator: "\n").map(String.init)
        let icons = entries.filter { entry in
            let lower = entry.lowercased()
            return lower.hasSuffix(".png")
                && lower.range(of: #"payload/[^/]+\.app/[^/]*appicon[^/]*\.png$"#, options: .regularExpression) != nil
        }
        guard !icons.isEmpty else { return nil }
        let chosen = icons.first { $0.lowercased().contains("60x60@2x") }
            ?? icons.first { $0.lowercased().contains("@2x") }
            ?? icons[0]
        guard let pngData = runUnzip(["-p", path, chosen]) else { return nil }
        return NSImage(data: pngData)
    }

    private func revealInFinder(_ url: URL) {
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    private func airDrop(_ url: URL) {
        guard let service = NSSharingService(named: .sendViaAirDrop) else { return }
        if service.canPerform(withItems: [url]) {
            service.perform(withItems: [url])
        }
    }

    private func installDownloaded(_ url: URL) {
        NSWorkspace.shared.open(url)
    }

    private func deleteDownloaded(_ url: URL) {
        try? FileManager.default.trashItem(at: url, resultingItemURL: nil)
        selectedDownloadedItemIDs = selectedDownloadedItemIDs.filter { $0 != url.path }
        if selectedDownloadedItemID == url.path {
            selectedDownloadedItemID = nil
        }
        refreshDownloadedFiles()
    }

    private func openDownloadedItemInSearch(_ item: DownloadedItem) {
        guard !item.appId.isEmpty else { return }
        selectedApp = searchResult(from: item)
        selectedAppLocalIconPath = item.id
        selectedVersion = nil
        selectedVersionIDs.removeAll()
        downloadAppID = item.appId
        downloadVersionID = item.versionId
        manualAppID = item.appId
        catalog.historyAppID = item.appId
        catalog.selectedSearchID = item.appId
        rightPanel = .search
        if item.isVisionApp {
            selectedSearchPlatformID = AppSearchPlatform.vision.rawValue
            catalog.platform = AppSearchPlatform.vision.rawValue
            catalog.historyProvider = "apple"
        }
        loadHistoryForActiveApp()
    }

    private func openDownloadedGroupInSearch(_ group: DownloadedAppGroup) {
        guard let item = group.items.first, !group.appId.isEmpty else { return }
        selectedApp = searchResult(from: item)
        selectedAppLocalIconPath = group.iconPath
        selectedVersion = nil
        selectedVersionIDs.removeAll()
        downloadAppID = group.appId
        downloadVersionID = ""
        manualAppID = group.appId
        manualVersionID = ""
        manualNoUpdate = false
        catalog.historyAppID = group.appId
        catalog.selectedSearchID = group.appId
        rightPanel = .search
        if group.isVisionApp {
            selectedSearchPlatformID = AppSearchPlatform.vision.rawValue
            catalog.platform = AppSearchPlatform.vision.rawValue
            catalog.historyProvider = "apple"
        }
        loadHistoryForActiveApp()
    }

    private func searchResult(from item: DownloadedItem) -> AppSearchResult {
        AppSearchResult(
            id: item.appId,
            name: item.appName.isEmpty ? "App ID \(item.appId)" : item.appName,
            artistName: item.developer,
            bundleId: item.bundleId,
            version: item.version,
            minimumOsVersion: "",
            price: "",
            fileSizeBytes: item.sizeBytes > 0 ? "\(item.sizeBytes)" : "",
            artworkUrl: item.artworkUrl,
            trackViewUrl: "",
            currentVersionReleaseDate: "",
            source: "downloaded",
            platform: item.softwarePlatform
        )
    }

    private func loadHistoryForActiveApp() {
        let appID = activeAppID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !appID.isEmpty else {
            catalog.versionStatus = String(localized: "请先选择 App。")
            return
        }

        catalog.historyAppID = appID
        appleVersionFetchNeedsAcquisition = false
        selectedVersion = nil
        selectedVersionIDs.removeAll()
        catalog.selectedVersionID = nil
        if activeAppIsVision && catalog.historyProvider != "apple" {
            selectedVersionIDs.removeAll()
            lastSelectedVersionID = nil
            catalog.versionResults = []
            catalog.versionStatus = String(localized: "Apple Vision Pro 的 App 历史版本目前仅在 Apple 来源提供，其他来源并未收录。")
            return
        }
        if catalog.historyProvider == "apple" || activeAppIsVision {
            fetchVersionIDsFromApple()
            return
        }
        catalog.loadVersions()
    }

    private func submitVerificationCode() {
        let cleanCode = pendingVerificationCode.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanCode.isEmpty else {
            saveMessage = String(localized: "请输入双重认证验证码。")
            showingVerificationPrompt = true
            return
        }

        pendingVerificationCode = ""
        showingVerificationPrompt = false

        let jobID = pendingCodeJobID
        pendingCodeJobID = nil
        if let jobID, downloads.job(jobID) != nil {
            saveMessage = String(localized: "正在完成 Apple 账户双重认证…")
            downloads.submitCode(id: jobID, code: cleanCode)
        } else {
            start(verificationCode: cleanCode)
        }
    }

    private func start(verificationCode: String = "", removeAppStoreUpdateMetadataOverride: Bool? = nil) {
        guard let account = accountStore.selectedAccount else {
            saveMessage = String(localized: "请先登录 Apple 账户。")
            showSettings()
            return
        }
        let cleanAppleAccount = account.appleAccount.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanPassword: String
        do {
            cleanPassword = try accountStore.password(for: account)
        } catch {
            saveMessage = error.localizedDescription
            return
        }
        let cleanCode = verificationCode.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanAppID = downloadAppID.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanVersionID = downloadVersionID.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanDir = downloadDir.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !cleanAppleAccount.isEmpty, !cleanPassword.isEmpty else {
            saveMessage = String(localized: "请先登录 Apple 账户。")
            showSettings()
            return
        }
        guard !cleanAppID.isEmpty else {
            rightPanel = .search
            return
        }
        guard !cleanDir.isEmpty else {
            return
        }

        let removeUpdateMetadata = removeAppStoreUpdateMetadataOverride ?? selectedVersion.map { noUpdateEnabled(for: $0) } ?? false
        let config = RunConfig(
            appleAccount: cleanAppleAccount,
            password: cleanPassword,
            code: cleanCode,
            appID: cleanAppID,
            versionID: cleanVersionID,
            downloadDir: cleanDir,
            removeAppStoreUpdateMetadata: removeUpdateMetadata
        )
        let variant = IPADownloadVariant(removeAppStoreUpdateMetadata: removeUpdateMetadata)
        let manualVersionKey = cleanVersionID.isEmpty ? "latest" : cleanVersionID
        let jobID = selectedVersion.map { downloadJobID(for: $0, removesAppStoreUpdates: removeUpdateMetadata) } ?? "manual-\(cleanAppID)-\(manualVersionKey)-\(variant.rawValue)"
        let labelVersion = selectedVersion?.version ?? (cleanVersionID.isEmpty ? String(localized: "最新版本") : cleanVersionID)
        let label = "\(activeAppName) \(labelVersion)\(removeUpdateMetadata ? " · 不再更新" : "")"
        downloads.start(id: jobID, label: label, config: config)
    }

    private func useSearchResult(_ result: AppSearchResult, openVersions: Bool) {
        downloadAppID = result.id
        manualAppID = result.id
        manualVersionID = ""
        manualNoUpdate = false
        selectedVersion = nil
        selectedVersionIDs.removeAll()
        catalog.historyAppID = result.id
        catalog.selectedSearchID = result.id

        if openVersions {
            rightPanel = .versions
            loadHistoryForActiveApp()
        }
    }

    private func useVersion(_ record: VersionRecord) {
        downloadAppID = catalog.historyAppID
        downloadVersionID = record.versionId
        manualAppID = catalog.historyAppID
        catalog.selectedVersionID = record.id
        catalog.versionStatus = String(localized: "已填入版本 ID：\(record.versionId)。")
    }

    private func chooseDownloadDir() {
        let panel = NSOpenPanel()
        panel.title = String(localized: "选择保存目录")
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = true
        if !downloadDir.isEmpty {
            panel.directoryURL = URL(fileURLWithPath: downloadDir, isDirectory: true)
        }

        if panel.runModal() == .OK, let url = panel.url {
            downloadDir = url.path
        }
    }

    private func openDownloadDir() {
        guard !downloadDir.isEmpty else { return }
        let url = URL(fileURLWithPath: downloadDir, isDirectory: true)
        NSWorkspace.shared.open(url)
    }
}

struct SearchResultRow: View {
    let result: AppSearchResult

    var body: some View {
        HStack(spacing: 12) {
            HStack(spacing: 10) {
                RetryingAsyncImage(url: URL(string: result.artworkUrl)) { image in
                    image
                        .resizable()
                        .scaledToFit()
                } placeholder: {
                    RoundedRectangle(cornerRadius: iconCornerRadius)
                        .fill(.quaternary)
                }
                .frame(width: 36, height: 36)
                .clipShape(RoundedRectangle(cornerRadius: iconCornerRadius))

                VStack(alignment: .leading, spacing: 2) {
                    Text(result.name.isEmpty ? result.id : result.name)
                        .lineLimit(1)
                    Text(result.artistName)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            Text(result.id)
                .frame(width: 110, alignment: .leading)
                .textSelection(.enabled)

            Text(result.bundleId)
                .frame(width: 210, alignment: .leading)
                .lineLimit(1)
                .textSelection(.enabled)

            Text(result.version)
                .frame(width: 90, alignment: .leading)
                .lineLimit(1)

            Text(result.fileSizeText)
                .frame(width: 80, alignment: .leading)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(.vertical, 7)
    }

    private var iconCornerRadius: CGFloat {
        result.isVisionApp ? 18 : 8
    }
}

struct AppSidebarRow: View {
    let rank: Int
    let result: AppSearchResult
    let isSelected: Bool
    @State private var isHovered = false
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        HStack(spacing: 10) {
            appIcon

            VStack(alignment: .leading, spacing: 3) {
                Text(result.name.isEmpty ? result.id : result.name)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(isSelected ? Color.white : Color.primary)
                    .lineLimit(1)
                Text(result.artistName)
                    .font(.caption)
                    .foregroundStyle(isSelected ? Color.white.opacity(0.78) : Color.secondary)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            Text(result.fileSizeText)
                .font(.caption)
                .foregroundStyle(isSelected ? Color.white.opacity(0.78) : Color.secondary)
                .lineLimit(1)
                .fixedSize()
                .frame(minWidth: 52, alignment: .trailing)
        }
        .padding(.horizontal, 10)
        .frame(height: 50)
        .background(rowFill, in: RoundedRectangle(cornerRadius: 13, style: .continuous))
        .contentShape(RoundedRectangle(cornerRadius: 13, style: .continuous))
        .onHover { isHovered = $0 }
    }

    private var rowFill: Color {
        if isSelected {
            return Color(nsColor: .selectedContentBackgroundColor)
        }
        if isHovered {
            return colorScheme == .dark ? Color.white.opacity(0.075) : Color.black.opacity(0.045)
        }
        return .clear
    }

    private var appIcon: some View {
        RetryingAsyncImage(url: URL(string: result.artworkUrl)) { image in
            image
                .resizable()
                .scaledToFill()
        } placeholder: {
            iconShape
                .fill(.quaternary)
        }
        .frame(width: 34, height: 34)
        .clipShape(iconShape)
        .overlay {
            iconShape
                .strokeBorder(Color(nsColor: .separatorColor).opacity(0.14), lineWidth: 0.5)
        }
        .compositingGroup()
        .shadow(color: .black.opacity(0.13), radius: 4, x: 0, y: 2)
    }

    private var iconShape: RoundedRectangle {
        RoundedRectangle(cornerRadius: result.isVisionApp ? 17 : 8.5, style: .continuous)
    }
}

private struct DownloadedAppSidebarRow: View {
    let group: DownloadedAppGroup
    let icon: NSImage?
    let isSelected: Bool
    @Binding var remoteIconCache: [String: NSImage]
    @State private var isHovered = false
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        HStack(spacing: 10) {
            appIcon

            VStack(alignment: .leading, spacing: 3) {
                Text(group.appName.isEmpty ? String(localized: "未知 App") : group.appName)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(isSelected ? Color.white : Color.primary)
                    .lineLimit(1)

                HStack(spacing: 5) {
                    Text(group.developer.isEmpty ? group.bundleId : group.developer)
                    Text("·")
                    Text(String(localized: "\(group.items.count) 个版本"))
                }
                .font(.caption)
                .foregroundStyle(isSelected ? Color.white.opacity(0.78) : Color.secondary)
                .lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

        }
        .padding(.horizontal, 10)
        .frame(height: 50)
        .background(rowFill, in: RoundedRectangle(cornerRadius: 13, style: .continuous))
        .contentShape(RoundedRectangle(cornerRadius: 13, style: .continuous))
        .onHover { isHovered = $0 }
    }

    private var rowFill: Color {
        if isSelected {
            return Color(nsColor: .selectedContentBackgroundColor)
        }
        if isHovered {
            return colorScheme == .dark ? Color.white.opacity(0.075) : Color.black.opacity(0.045)
        }
        return .clear
    }

    private var appIcon: some View {
        Group {
            if let icon {
                Image(nsImage: icon)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFill()
            } else if !group.artworkUrl.isEmpty {
                CachedRemoteAppIcon(
                    urlString: group.artworkUrl,
                    size: 34,
                    cornerRadius: iconCornerRadius,
                    cache: $remoteIconCache
                )
            } else {
                RoundedRectangle(cornerRadius: iconCornerRadius, style: .continuous)
                    .fill(.quaternary)
                    .overlay {
                        Image(systemName: "app")
                            .font(.system(size: 15))
                            .foregroundStyle(.secondary)
                    }
            }
        }
        .frame(width: 34, height: 34)
        .clipShape(RoundedRectangle(cornerRadius: iconCornerRadius, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: iconCornerRadius, style: .continuous)
                .strokeBorder(Color(nsColor: .separatorColor).opacity(0.14), lineWidth: 0.5)
        }
        .compositingGroup()
        .shadow(color: .black.opacity(0.13), radius: 4, x: 0, y: 2)
    }

    private var iconCornerRadius: CGFloat {
        group.isVisionApp ? 17 : 8.5
    }
}

private struct DownloadedVersionHistoryRow: View {
    struct Columns {
        let version: CGFloat
        let versionID: CGFloat
        let size: CGFloat
        let region: CGFloat
        let account: CGFloat
        let noUpdates: CGFloat
    }

    static let iconColumnWidth: CGFloat = 50
    static let accountToNoUpdatesGap: CGFloat = 22
    static let actionGap: CGFloat = 12
    static let actionColumnWidth: CGFloat = 104
    static let rowHorizontalPadding: CGFloat = 16

    static func columns(for fullWidth: CGFloat) -> Columns {
        let baseVersion: CGFloat = 94
        let baseVersionID: CGFloat = 128
        let baseSize: CGFloat = 88
        let baseRegion: CGFloat = 86
        let baseAccount: CGFloat = 184
        let baseNoUpdates: CGFloat = 74
        let natural = baseVersion + baseVersionID + baseSize + baseRegion + baseAccount + accountToNoUpdatesGap + baseNoUpdates
        let reserved = rowHorizontalPadding * 2 + iconColumnWidth + actionGap + actionColumnWidth
        let available = max(1, fullWidth - reserved)

        if available < natural {
            let scale = available / natural
            return Columns(
                version: baseVersion * scale,
                versionID: baseVersionID * scale,
                size: baseSize * scale,
                region: baseRegion * scale,
                account: baseAccount * scale,
                noUpdates: baseNoUpdates * scale
            )
        }

        let extra = available - natural
        return Columns(
            version: baseVersion + extra * 0.12,
            versionID: baseVersionID + extra * 0.20,
            size: baseSize + extra * 0.10,
            region: baseRegion + extra * 0.10,
            account: baseAccount + extra * 0.36,
            noUpdates: baseNoUpdates + extra * 0.10
        )
    }

    static func visualDividerOffsets(for columns: Columns) -> [CGFloat] {
        let start = rowHorizontalPadding + iconColumnWidth
        let visualShift: CGFloat = 7
        return [
            start + columns.version - visualShift,
            start + columns.version + columns.versionID - visualShift,
            start + columns.version + columns.versionID + columns.size - visualShift,
            start + columns.version + columns.versionID + columns.size + columns.region - visualShift,
            start + columns.version + columns.versionID + columns.size + columns.region + columns.account + accountToNoUpdatesGap - visualShift
        ]
    }

    let item: DownloadedItem
    let icon: NSImage?
    let rowIndex: Int
    let isSelected: Bool
    @Binding var remoteIconCache: [String: NSImage]
    let onSelect: () -> Void
    let onReveal: () -> Void
    let onAirDrop: () -> Void
    let onDelete: () -> Void
    @State private var isHovered = false
    @Namespace private var actionGlassNamespace
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        GeometryReader { proxy in
            let columns = Self.columns(for: proxy.size.width)
            let region = appStoreRegion(item.storefrontId)

            HStack(spacing: 0) {
                rowIcon

                Text(item.version.isEmpty ? "—" : item.version)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(primaryTextStyle)
                    .lineLimit(1)
                    .frame(width: columns.version, alignment: .leading)

                HoverCopyIDText(value: item.versionId, isVisible: isHovered, isSelected: isSelected)
                    .frame(width: columns.versionID, alignment: .leading)

                Text(item.sizeText)
                    .font(.callout)
                    .foregroundStyle(secondaryTextStyle)
                    .lineLimit(1)
                    .frame(width: columns.size, alignment: .leading)

                Text(region.name)
                    .font(.callout)
                    .foregroundStyle(secondaryTextStyle)
                    .lineLimit(1)
                    .frame(width: columns.region, alignment: .leading)

                Text(item.appleAccount.isEmpty ? "—" : item.appleAccount)
                    .font(.callout)
                    .foregroundStyle(secondaryTextStyle)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(width: columns.account, alignment: .leading)

                Color.clear.frame(width: Self.accountToNoUpdatesGap, height: 1)

                Text(item.removesAppStoreUpdates ? String(localized: "是") : String(localized: "否"))
                    .font(.callout)
                    .foregroundStyle(secondaryTextStyle)
                    .lineLimit(1)
                    .frame(width: columns.noUpdates, alignment: .leading)

                Color.clear.frame(width: Self.actionGap, height: 1)

                FileActionsBar(isSelected: isSelected, onReveal: onReveal, onAirDrop: onAirDrop, onDelete: onDelete)
                    .frame(width: Self.actionColumnWidth, alignment: .trailing)
            }
            .padding(.horizontal, Self.rowHorizontalPadding)
            .frame(width: proxy.size.width, height: 46, alignment: .leading)
        }
        .frame(maxWidth: .infinity, minHeight: 46, maxHeight: 46, alignment: .leading)
        .background(rowFill, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
        .contentShape(RoundedRectangle(cornerRadius: 11, style: .continuous))
        .onTapGesture {
            onSelect()
        }
        .onHover { isHovered = $0 }
    }

    private var rowIcon: some View {
        Group {
            if let icon {
                Image(nsImage: icon)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFill()
            } else if !item.artworkUrl.isEmpty {
                CachedRemoteAppIcon(
                    urlString: item.artworkUrl,
                    size: 24,
                    cornerRadius: rowIconCornerRadius,
                    cache: $remoteIconCache
                )
            } else {
                RoundedRectangle(cornerRadius: rowIconCornerRadius, style: .continuous)
                    .fill(.quaternary)
                    .overlay {
                        Image(systemName: "app")
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
                    }
            }
        }
        .frame(width: 24, height: 24)
        .clipShape(RoundedRectangle(cornerRadius: rowIconCornerRadius, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: rowIconCornerRadius, style: .continuous)
                .strokeBorder(Color(nsColor: .separatorColor).opacity(0.14), lineWidth: 0.5)
        }
        .frame(width: Self.iconColumnWidth, alignment: .center)
        .offset(x: -4)
        .shadow(color: .black.opacity(colorScheme == .dark ? 0.22 : 0.12), radius: 4, x: 0, y: 2)
    }

    private var rowIconCornerRadius: CGFloat {
        item.isVisionApp ? 12 : 6
    }

    private var rowFill: Color {
        if isSelected {
            return Color(nsColor: .selectedContentBackgroundColor)
        }
        if isHovered {
            return colorScheme == .dark ? Color.white.opacity(0.075) : Color.black.opacity(0.045)
        }
        if rowIndex.isMultiple(of: 2) {
            return colorScheme == .dark ? Color.white.opacity(0.030) : Color.black.opacity(0.022)
        }
        return .clear
    }

    private var primaryTextStyle: Color {
        isSelected ? Color.white : Color.primary
    }

    private var secondaryTextStyle: Color {
        isSelected ? Color.white.opacity(0.80) : Color.secondary
    }
}

private struct SourceProviderCapsule: View {
    let selection: String
    let isDisabled: Bool
    let onSelect: (String) -> Void
    @State private var hoveredProvider: String?
    @Environment(\.colorScheme) private var colorScheme

    private var providers: [(id: String, title: String)] {
        [
            ("auto", String(localized: "自动")),
            ("timbrd", "Timbrd"),
            ("agzy", "Agzy"),
            ("bilin", "Bilin"),
            ("apple", "Apple"),
        ]
    }

    var body: some View {
        HStack(spacing: 0) {
            ForEach(providers.indices, id: \.self) { index in
                let provider = providers[index]
                let isSelected = selection == provider.id
                Button {
                    guard !isDisabled else { return }
                    onSelect(provider.id)
                } label: {
                    Text(provider.title)
                        .font(.callout.weight(isSelected ? .semibold : .regular))
                        .lineLimit(1)
                        .minimumScaleFactor(0.84)
                        .frame(maxWidth: .infinity, minHeight: 30)
                        .padding(.horizontal, 8)
                        .foregroundStyle(isSelected ? Color.white : Color.primary)
                        .background {
                            if isSelected {
                                Capsule()
                                    .fill(Color(nsColor: .selectedContentBackgroundColor))
                            } else if hoveredProvider == provider.id && !isDisabled {
                                Capsule()
                                    .fill(providerHoverFill)
                            }
                        }
                        .contentShape(Capsule())
                }
                .buttonStyle(StablePressButtonStyle())
                .onHover { hovering in
                    hoveredProvider = hovering ? provider.id : (hoveredProvider == provider.id ? nil : hoveredProvider)
                }

                if index < providers.count - 1 {
                    Rectangle()
                        .fill(providerDividerFill)
                        .frame(width: 1, height: 18)
                        .padding(.horizontal, 2)
                        .opacity(shouldShowDivider(after: index) ? 1 : 0)
                }
            }
        }
        .padding(3)
        .frame(height: 36)
        .background(providerBaseFill, in: Capsule())
        .overlay {
            Capsule()
                .stroke(providerStroke, lineWidth: 1)
        }
        .glassEffect(.regular.tint(providerGlassTint).interactive(), in: Capsule())
        .opacity(isDisabled ? 0.55 : 1)
        .allowsHitTesting(!isDisabled)
    }

    private func shouldShowDivider(after index: Int) -> Bool {
        guard index < providers.count - 1 else { return false }
        let left = providers[index].id
        let right = providers[index + 1].id
        return left != selection
            && right != selection
            && left != hoveredProvider
            && right != hoveredProvider
    }

    private var providerBaseFill: Color {
        colorScheme == .dark ? Color.white.opacity(0.07) : Color.black.opacity(0.06)
    }

    private var providerHoverFill: Color {
        colorScheme == .dark ? Color.white.opacity(0.12) : Color.black.opacity(0.08)
    }

    private var providerGlassTint: Color {
        colorScheme == .dark ? Color(red: 0.10, green: 0.12, blue: 0.16).opacity(0.25) : Color.white.opacity(0.36)
    }

    private var providerStroke: Color {
        colorScheme == .dark ? Color.white.opacity(0.14) : Color.black.opacity(0.035)
    }

    private var providerDividerFill: Color {
        colorScheme == .dark ? Color.white.opacity(0.16) : Color(nsColor: .separatorColor).opacity(0.34)
    }
}

private struct AccountSelectionButton: View {
    let isSelected: Bool
    let action: () -> Void
    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(isSelected ? Color.accentColor : Color.secondary)
                .frame(width: 24, height: 24)
                .background {
                    if isHovered {
                        Circle()
                            .fill(Color.primary.opacity(0.07))
                    }
                }
        }
        .buttonStyle(StablePressButtonStyle())
        .onHover { isHovered = $0 }
    }
}

private struct SettingsHoverIconButton: View {
    let systemImage: String
    let help: String
    let action: () -> Void
    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            Image(systemName: systemImage)
                .font(.system(size: 16, weight: .medium))
                .foregroundStyle(.primary)
                .frame(width: 28, height: 28)
                .background {
                    if isHovered {
                        Circle()
                            .fill(Color.primary.opacity(0.075))
                    }
                }
        }
        .buttonStyle(StablePressButtonStyle())
        .onHover { isHovered = $0 }
    }
}

struct VersionResultRow: View {
    let record: VersionRecord
    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 0) {
            Text(record.version)
                .frame(width: 170, alignment: .leading)
                .lineLimit(1)

            HoverCopyIDText(value: record.versionId, isVisible: isHovered, isSelected: false)
                .frame(width: 190, alignment: .leading)

            Text(record.size.isEmpty ? "-" : record.size)
                .frame(width: 130, alignment: .leading)
                .foregroundStyle(.secondary)
                .lineLimit(1)

            Text(record.source)
                .frame(width: 110, alignment: .leading)
                .foregroundStyle(.secondary)
                .lineLimit(1)

            Spacer()
            Text("")
                .frame(width: 82)
        }
        .padding(.vertical, 7)
        .onHover { isHovered = $0 }
    }
}

struct AppSearchTile: View {
    let rank: Int
    let result: AppSearchResult
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 10) {
            appIcon
                .padding(.leading, 4)

            Text("\(rank)")
                .font(.headline.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 22, alignment: .trailing)

            VStack(alignment: .leading, spacing: 4) {
                Text(result.name.isEmpty ? result.id : result.name)
                    .font(.headline)
                    .lineLimit(1)

                Text(result.artistName)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)

                if !result.version.isEmpty || !result.fileSizeText.isEmpty {
                    HStack(spacing: 8) {
                        if !result.version.isEmpty {
                            Label(result.version, systemImage: "sparkle")
                        }
                        if !result.fileSizeText.isEmpty {
                            Label(result.fileSizeText, systemImage: "internaldrive")
                        }
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                }
            }

            Spacer(minLength: 8)

            Text(isSelected ? String(localized: "已选") : String(localized: "前往"))
                .font(.caption.weight(.semibold))
                .foregroundStyle(isSelected ? .white : Color.accentColor)
                .padding(.horizontal, 13)
                .frame(height: 28)
                .background {
                    Capsule()
                        .fill(isSelected ? Color(nsColor: .selectedContentBackgroundColor) : Color.primary.opacity(0.07))
                        .overlay {
                            if !isSelected {
                                Capsule()
                                    .stroke(Color(nsColor: .separatorColor).opacity(0.18), lineWidth: 1)
                            }
                        }
                }
        }
        .padding(.vertical, 12)
        .padding(.trailing, 6)
        .contentShape(Rectangle())
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(Color(nsColor: .separatorColor).opacity(0.55))
                .frame(height: 1)
                .padding(.leading, 86)
        }
    }

    private var appIcon: some View {
        RetryingAsyncImage(url: URL(string: result.artworkUrl)) { image in
            image
                .resizable()
                .scaledToFill()
        } placeholder: {
            iconShape
                .fill(.quaternary)
        }
        .frame(width: 48, height: 48)
        .clipShape(iconShape)
        .overlay {
            iconShape
                .strokeBorder(Color(nsColor: .separatorColor).opacity(0.14), lineWidth: 0.5)
        }
        .compositingGroup()
        .shadow(color: .black.opacity(0.16), radius: 5, x: 0, y: 2)
    }

    private var iconShape: RoundedRectangle {
        RoundedRectangle(cornerRadius: result.isVisionApp ? 24 : 12.5, style: .continuous)
    }
}

struct AppStoreSearchResultRow: View {
    let rank: Int
    let result: AppSearchResult
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 16) {
            RetryingAsyncImage(url: URL(string: result.artworkUrl)) { image in
                image
                    .resizable()
                    .scaledToFit()
            } placeholder: {
                RoundedRectangle(cornerRadius: iconCornerRadius, style: .continuous)
                    .fill(.quaternary)
            }
            .frame(width: 64, height: 64)
            .clipShape(RoundedRectangle(cornerRadius: iconCornerRadius, style: .continuous))
            .shadow(color: .black.opacity(0.12), radius: 5, y: 2)

            Text("\(rank)")
                .font(.title3.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 34, alignment: .trailing)

            VStack(alignment: .leading, spacing: 4) {
                Text(result.name.isEmpty ? result.id : result.name)
                    .font(.headline)
                    .lineLimit(1)

                Text(result.artistName)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)

                HStack(spacing: 12) {
                    Label(result.version.isEmpty ? String(localized: "版本未知") : result.version, systemImage: "sparkle")
                    if !result.fileSizeText.isEmpty {
                        Label(result.fileSizeText, systemImage: "internaldrive")
                    }
                    Label(result.id, systemImage: "app.badge")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            }

            Spacer(minLength: 12)

            Image(systemName: isSelected ? "checkmark.circle.fill" : "icloud.and.arrow.down")
                .font(.title3.weight(.semibold))
                .foregroundStyle(isSelected ? Color.accentColor : Color.accentColor)
                .frame(width: 40)
        }
        .padding(.vertical, 16)
        .contentShape(Rectangle())
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(Color(nsColor: .separatorColor).opacity(0.55))
                .frame(height: 1)
                .padding(.leading, 114)
        }
    }

    private var iconCornerRadius: CGFloat {
        result.isVisionApp ? 32 : 14
    }
}

struct AppSelectionCard: View {
    let result: AppSearchResult
    let isSelected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 12) {
                RetryingAsyncImage(url: URL(string: result.artworkUrl)) { image in
                    image
                        .resizable()
                        .scaledToFit()
                } placeholder: {
                    RoundedRectangle(cornerRadius: iconCornerRadius, style: .continuous)
                        .fill(.quaternary)
                }
                .frame(width: 58, height: 58)
                .clipShape(RoundedRectangle(cornerRadius: iconCornerRadius, style: .continuous))
                .shadow(color: .black.opacity(0.12), radius: 5, y: 2)

                Spacer()

                Image(systemName: isSelected ? "checkmark.circle.fill" : "chevron.right.circle")
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(isSelected ? Color.accentColor : .secondary)
            }

            VStack(alignment: .leading, spacing: 5) {
                Text(result.name.isEmpty ? result.id : result.name)
                    .font(.headline)
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)

                Text(result.artistName)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 4)

            VStack(alignment: .leading, spacing: 6) {
                Label(result.id, systemImage: "app.badge")
                Label(result.version.isEmpty ? String(localized: "版本未知") : result.version, systemImage: "sparkle")
                if !result.fileSizeText.isEmpty {
                    Label(result.fileSizeText, systemImage: "internaldrive")
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .padding(20)
        .frame(height: 230)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 26, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 26, style: .continuous)
                .stroke(isSelected ? Color.accentColor.opacity(0.55) : Color(nsColor: .separatorColor).opacity(0.25), lineWidth: isSelected ? 2 : 1)
        }
    }

    private var iconCornerRadius: CGFloat {
        result.isVisionApp ? 29 : 14
    }
}

struct VersionSelectionRow: View {
    struct Columns {
        let version: CGFloat
        let versionID: CGFloat
        let size: CGFloat
        let noUpdates: CGFloat
    }

    static let iconColumnWidth: CGFloat = 50
    static let versionColumnWidth: CGFloat = 132
    static let versionIDColumnWidth: CGFloat = 178
    static let sizeColumnWidth: CGFloat = 118
    static let noUpdatesColumnWidth: CGFloat = 112
    static let noUpdatesToggleTrailingInset: CGFloat = 8
    static let noUpdatesSwitchApproxWidth: CGFloat = 48
    static let noUpdatesHeaderDividerGap: CGFloat = 8
    static let actionGap: CGFloat = 12
    static var actionColumnWidth: CGFloat {
        usesWideDownloadButton ? 112 : 96
    }
    static var downloadButtonWidth: CGFloat {
        usesWideDownloadButton ? 82 : 58
    }
    static let rowHorizontalPadding: CGFloat = 16

    static var usesWideDownloadButton: Bool {
        let code = AppLanguage.effectiveCode.lowercased()
        return code.hasPrefix("en") || code.hasPrefix("ja")
    }

    static func columns(for fullWidth: CGFloat) -> Columns {
        let baseVersion: CGFloat = 126
        let baseVersionID: CGFloat = 196
        let baseSize: CGFloat = 118
        let baseNoUpdates: CGFloat = noUpdatesColumnWidth
        let natural = baseVersion + baseVersionID + baseSize + baseNoUpdates
        let reserved = rowHorizontalPadding * 2 + iconColumnWidth + actionGap + actionColumnWidth
        let available = max(1, fullWidth - reserved)

        if available < natural {
            let scale = available / natural
            return Columns(
                version: baseVersion * scale,
                versionID: baseVersionID * scale,
                size: baseSize * scale,
                noUpdates: baseNoUpdates * scale
            )
        }

        let extra = available - natural
        return Columns(
            version: baseVersion + extra * 0.28,
            versionID: baseVersionID + extra * 0.48,
            size: baseSize + extra * 0.24,
            noUpdates: baseNoUpdates
        )
    }

    static func noUpdatesHeaderInset(for columns: Columns) -> CGFloat {
        max(0, columns.noUpdates - noUpdatesToggleTrailingInset - noUpdatesSwitchApproxWidth)
    }

    static func visualDividerOffsets(for columns: Columns) -> [CGFloat] {
        let start = rowHorizontalPadding + iconColumnWidth
        let visualShift: CGFloat = 7
        let noUpdatesDividerInset = max(12, noUpdatesHeaderInset(for: columns) - noUpdatesHeaderDividerGap)
        return [
            start + columns.version - visualShift,
            start + columns.version + columns.versionID - visualShift,
            start + columns.version + columns.versionID + columns.size + noUpdatesDividerInset
        ]
    }

    let record: VersionRecord
    let rowIndex: Int
    let isSelected: Bool
    let removesAppStoreUpdates: Bool
    let isDownloading: Bool
    let downloadProgress: Double?
    let isPackaging: Bool
    let hasError: Bool
    let errorLog: String
    let downloadedURL: URL?
    let appIcon: NSImage?
    let onSelect: () -> Void
    let onToggleNoUpdate: (Bool) -> Void
    let onDownload: () -> Void
    let onReveal: () -> Void
    let onAirDrop: () -> Void
    let onDelete: () -> Void
    @State private var isHovered = false
    @Namespace private var actionGlassNamespace
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        GeometryReader { proxy in
            let columns = Self.columns(for: proxy.size.width)

            HStack(spacing: 0) {
                rowIcon

                Text(record.version)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(primaryTextStyle)
                    .lineLimit(1)
                    .frame(width: columns.version, alignment: .leading)

                HoverCopyIDText(value: record.versionId, isVisible: isHovered, isSelected: isSelected)
                    .frame(width: columns.versionID, alignment: .leading)

                Text(record.size.isEmpty ? "-" : record.size)
                    .font(.callout)
                    .frame(width: columns.size, alignment: .leading)
                    .foregroundStyle(secondaryTextStyle)
                    .lineLimit(1)

                HStack(spacing: 0) {
                    Spacer(minLength: 0)
                    Toggle("", isOn: Binding(
                        get: { removesAppStoreUpdates },
                        set: { enabled in
                            withAnimation(.smooth(duration: 0.22)) {
                                onToggleNoUpdate(enabled)
                            }
                        }
                    ))
                    .labelsHidden()
                    .toggleStyle(.switch)
                    .controlSize(.small)
                    .fixedSize()
                }
                .padding(.trailing, Self.noUpdatesToggleTrailingInset)
                .frame(width: columns.noUpdates, alignment: .trailing)
                .help(String(localized: "下载后不再显示 App Store 更新"))

                Color.clear
                    .frame(width: Self.actionGap, height: 1)

                actionSlot
            }
            .padding(.horizontal, Self.rowHorizontalPadding)
            .frame(width: proxy.size.width, height: 46, alignment: .leading)
        }
        .frame(maxWidth: .infinity, minHeight: 46, maxHeight: 46, alignment: .leading)
        .background(rowFill, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
        .contentShape(RoundedRectangle(cornerRadius: 11, style: .continuous))
        .simultaneousGesture(TapGesture().onEnded {
            onSelect()
        })
        .onHover { isHovered = $0 }
    }

    private var rowIcon: some View {
        Group {
            if let appIcon {
                Image(nsImage: appIcon)
                    .resizable()
                    .interpolation(.high)
                    .frame(width: 24, height: 24)
                    .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            } else {
                Color.clear.frame(width: 24, height: 24)
            }
        }
        .frame(width: VersionSelectionRow.iconColumnWidth, alignment: .center)
        .offset(x: -4)
        .shadow(color: Color.black.opacity(colorScheme == .dark ? 0.24 : 0.14), radius: 4, x: 0, y: 2)
    }

    @ViewBuilder
    private var actionSlot: some View {
        GlassEffectContainer(spacing: 0) {
            ZStack(alignment: .trailing) {
                actionContent
                    .id(actionState)
            }
        }
        .frame(width: Self.actionColumnWidth, alignment: .trailing)
        .animation(.smooth(duration: 0.32), value: actionState)
    }

    @ViewBuilder
    private var actionContent: some View {
        switch actionState {
        case .error:
            DownloadErrorIndicator(message: errorMessage, retry: onDownload)
        case .running:
            DownloadProgressPill(progress: downloadProgress, isPackaging: isPackaging)
                .glassEffectID("version-row-action", in: actionGlassNamespace)
                .glassEffectTransition(.matchedGeometry)
        case .downloaded:
            FileActionsBar(isSelected: isSelected, onReveal: onReveal, onAirDrop: onAirDrop, onDelete: onDelete)
                .glassEffectID("version-row-action", in: actionGlassNamespace)
                .glassEffectTransition(.matchedGeometry)
        case .ready:
            Button {
                onDownload()
            } label: {
                Text(String(localized: "下载"))
                    .font(.caption.weight(.semibold))
                    .frame(width: VersionSelectionRow.downloadButtonWidth, height: 26)
                    .background {
                        if isSelected {
                            Capsule()
                                .fill(Color.white.opacity(0.56))
                        }
                    }
                    .overlay {
                        if isSelected {
                            Capsule()
                                .stroke(Color.white.opacity(0.48), lineWidth: 1)
                        }
                    }
            }
            .buttonStyle(StablePressButtonStyle())
            .foregroundStyle(Color.accentColor)
            .glassEffect(.regular.tint(isSelected ? Color.white.opacity(0.34) : nil).interactive(), in: Capsule())
            .glassEffectID("version-row-action", in: actionGlassNamespace)
            .glassEffectTransition(.matchedGeometry)
        }
    }

    private enum ActionState: Hashable {
        case error
        case running
        case downloaded
        case ready
    }

    private var actionState: ActionState {
        if hasError { return .error }
        if isDownloading { return .running }
        if downloadedURL != nil { return .downloaded }
        return .ready
    }

    private var rowFill: Color {
        if isSelected {
            return Color(nsColor: .selectedContentBackgroundColor)
        }
        if isHovered {
            return colorScheme == .dark ? Color.white.opacity(0.10) : Color.black.opacity(0.055)
        }
        if rowIndex.isMultiple(of: 2) {
            return colorScheme == .dark ? Color.white.opacity(0.030) : Color.black.opacity(0.022)
        }
        return .clear
    }

    private var primaryTextStyle: Color {
        isSelected ? Color.white : Color.primary
    }

    private var secondaryTextStyle: Color {
        isSelected ? Color.white.opacity(0.80) : Color.secondary
    }

    private var errorMessage: String {
        downloadErrorMessage(from: errorLog)
    }
}

private struct DownloadErrorIndicator: View {
    let message: String
    let retry: () -> Void
    @State private var showingDetails = false

    var body: some View {
        Button(action: retry) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.yellow)
                .frame(width: 58, height: 26)
                .contentShape(Capsule())
        }
        .buttonStyle(StablePressButtonStyle())
        .glassEffect(.regular.tint(Color.yellow.opacity(0.18)).interactive(), in: Capsule())
        .onHover { showingDetails = $0 }
        .popover(isPresented: $showingDetails, arrowEdge: .top) {
            VStack(alignment: .leading, spacing: 10) {
                Label(String(localized: "下载失败"), systemImage: "exclamationmark.triangle.fill")
                    .font(.headline)
                    .foregroundStyle(.yellow)

                ScrollView {
                    Text(message)
                        .font(.caption)
                        .foregroundStyle(.primary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                .frame(width: 360)
                .frame(maxHeight: 220)
                }
            .padding(14)
            .presentationBackground(.ultraThinMaterial)
        }
    }
}

private struct RowActionButton<Content: View>: View {
    let help: String
    let action: () -> Void
    @ViewBuilder var content: () -> Content
    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            content()
                .frame(width: 34, height: 30)
                .background(isHovered ? Color.primary.opacity(0.08) : Color.clear,
                            in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                .contentShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
    }
}

private struct AppIDCopyLine: View {
    let appID: String
    let fallback: String

    var body: some View {
        let trimmedAppID = appID.trimmingCharacters(in: .whitespacesAndNewlines)

        Group {
            if trimmedAppID.isEmpty {
                Text(fallback)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            } else {
                HStack(spacing: 5) {
                    Text("App ID \(trimmedAppID)")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)

                    CopyGlyphButton(value: trimmedAppID, isSelected: false)
                }
            }
        }
    }
}

private struct HoverCopyIDText: View {
    let value: String
    let isVisible: Bool
    let isSelected: Bool
    var font: Font = .callout.monospacedDigit()

    var body: some View {
        let trimmedValue = value.trimmingCharacters(in: .whitespacesAndNewlines)

        HStack(spacing: 5) {
            Text(trimmedValue.isEmpty ? "—" : trimmedValue)
                .font(font)
                .foregroundStyle(isSelected ? Color.white.opacity(0.80) : Color.secondary)
                .lineLimit(1)
                .textSelection(.disabled)

            if isVisible && !trimmedValue.isEmpty {
                CopyGlyphButton(value: trimmedValue, isSelected: isSelected)
                .transition(.opacity)
            }
        }
        .animation(.easeOut(duration: 0.12), value: isVisible)
    }
}

private struct CopyGlyphButton: View {
    let value: String
    let isSelected: Bool
    @State private var copied = false

    var body: some View {
        Button {
            copyToPasteboard(value)
            copied = true
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 1_400_000_000)
                copied = false
            }
        } label: {
            Image(systemName: copied ? "checkmark" : "document.on.document")
                .font(.system(size: 11.5, weight: .semibold))
                .symbolRenderingMode(.hierarchical)
                .frame(width: 18, height: 18)
                .contentShape(Circle())
        }
        .buttonStyle(.borderless)
        .foregroundStyle(buttonTint)
    }

    private var buttonTint: Color {
        isSelected ? Color.white.opacity(0.78) : Color.secondary
    }
}

private struct FileActionsBar: View {
    let isSelected: Bool
    let onReveal: () -> Void
    let onAirDrop: () -> Void
    let onDelete: () -> Void

    var body: some View {
        HStack(spacing: 0) {
            FileActionButton(systemImage: "finder", tint: .secondary, size: 14.5, help: String(localized: "在访达中显示"), action: onReveal)
            FileActionButton(systemImage: "square.and.arrow.up", tint: Color.accentColor, size: 13, yOffset: -1, help: String(localized: "通过 AirDrop 发送"), action: onAirDrop)
            FileActionButton(systemImage: "trash", tint: .red, size: 13.5, help: String(localized: "删除本地文件"), action: onDelete)
        }
        .padding(2)
        .glassEffect(.regular, in: Capsule())
    }
}

private struct FileActionButton: View {
    let systemImage: String
    let tint: Color
    let size: CGFloat
    var yOffset: CGFloat = 0
    let help: String
    let action: () -> Void
    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            Image(systemName: systemImage)
                .font(.system(size: size, weight: .regular))
                .foregroundStyle(tint)
                .offset(y: yOffset)
                .frame(width: 26, height: 26)
                .background(isHovered ? Color.primary.opacity(0.10) : Color.clear, in: Circle())
                .contentShape(Circle())
        }
        .buttonStyle(StablePressButtonStyle())
        .onHover { isHovered = $0 }
    }
}

private struct CachedRemoteAppIcon: View {
    let urlString: String
    let size: CGFloat
    let cornerRadius: CGFloat
    @Binding var cache: [String: NSImage]

    var body: some View {
        Group {
            if let image = cache[urlString] {
                Image(nsImage: image)
                    .resizable()
                    .interpolation(.high)
                    .scaledToFill()
            } else {
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(.quaternary)
            }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .strokeBorder(Color(nsColor: .separatorColor).opacity(0.14), lineWidth: 0.5)
        }
        .task(id: urlString) {
            await loadIfNeeded()
        }
    }

    private func loadIfNeeded() async {
        guard cache[urlString] == nil,
              let url = URL(string: urlString),
              let (data, _) = try? await URLSession.shared.data(from: url),
              let image = NSImage(data: data) else {
            return
        }
        await MainActor.run {
            cache[urlString] = image
        }
    }
}

private struct RetryingAsyncImage<Content: View, Placeholder: View>: View {
    let url: URL?
    var maxRetries: Int = 4
    @ViewBuilder let content: (Image) -> Content
    @ViewBuilder let placeholder: () -> Placeholder

    @State private var reloadToken = 0
    @State private var attempts = 0

    init(url: URL?,
         @ViewBuilder content: @escaping (Image) -> Content,
         @ViewBuilder placeholder: @escaping () -> Placeholder) {
        self.url = url
        self.content = content
        self.placeholder = placeholder
    }

    var body: some View {
        AsyncImage(url: url) { phase in
            switch phase {
            case .success(let image):
                content(image)
            case .failure:
                placeholder().onAppear(perform: scheduleRetry)
            case .empty:
                placeholder()
            @unknown default:
                placeholder()
            }
        }
        .id(reloadToken)
        .onChange(of: url) { _, _ in attempts = 0; reloadToken += 1 }
    }

    private func scheduleRetry() {
        guard url != nil, attempts < maxRetries else { return }
        let delay = Double(attempts + 1) * 0.7
        attempts += 1
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            reloadToken += 1
        }
    }
}

private struct DownloadProgressPill: View {
    let progress: Double?
    var isPackaging: Bool = false

    private var normalizedProgress: Double {
        min(max(progress ?? 0, 0), 1)
    }

    private var fillFraction: Double {
        isPackaging ? 1 : normalizedProgress
    }

    private var progressPercent: Int? {
        if isPackaging { return 100 }
        guard let progress else { return nil }
        return Int((min(max(progress, 0), 1) * 100).rounded())
    }

    var body: some View {
        GeometryReader { proxy in
            let fillWidth = proxy.size.width * fillFraction

            ZStack(alignment: .leading) {
                Capsule()
                    .fill(Color.accentColor.opacity(0.16))
                Capsule()
                    .fill(Color.accentColor.opacity(0.92))
                    .frame(width: fillWidth)

                progressLabel(foregroundStyle: Color.accentColor)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                progressLabel(foregroundStyle: Color.white)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .mask(alignment: .leading) {
                        Rectangle()
                            .frame(width: fillWidth)
                    }
            }
        }
        .frame(width: 58, height: 26)
        .clipShape(Capsule())
        .glassEffect(.regular.tint(Color.accentColor.opacity(0.12)).interactive(), in: Capsule())
    }

    @ViewBuilder
    private func progressLabel(foregroundStyle: Color) -> some View {
        if let progressPercent {
            Text("\(progressPercent)%")
                .contentTransition(.numericText(value: Double(progressPercent)))
                .animation(.smooth(duration: 0.28), value: progressPercent)
                .foregroundStyle(foregroundStyle)
                .font(.caption.weight(.semibold))
                .monospacedDigit()
        } else {
            Text(String(localized: "下载中"))
                .foregroundStyle(foregroundStyle)
                .font(.caption.weight(.semibold))
                .monospacedDigit()
        }
    }

    private var progressText: String {
        guard let progressPercent else { return String(localized: "下载中") }
        return "\(progressPercent)%"
    }
}

struct SelectionSummaryCard: View {
    let title: String
    let primary: String
    let secondary: String
    let systemImage: String

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: systemImage)
                .font(.title3.weight(.semibold))
                .frame(width: 42, height: 42)
                .background(.thinMaterial, in: Circle())

            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(primary)
                    .font(.headline)
                    .lineLimit(1)
                Text(secondary)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer()
        }
        .padding(18)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
    }
}

struct SidebarSection<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(title)
                .font(.headline)

            VStack(alignment: .leading, spacing: 14) {
                content
            }
        }
    }
}

private struct SidebarControlButtonStyleModifier: ViewModifier {
    func body(content: Content) -> some View {
        content
            .buttonStyle(.bordered)
            .buttonBorderShape(.capsule)
            .controlSize(.large)
            .font(.body)
    }
}

private struct SidebarActionButtonStyleModifier: ViewModifier {
    func body(content: Content) -> some View {
        content
            .buttonStyle(.glass)
            .controlSize(.large)
            .font(.body)
    }
}

private struct StablePressButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
    }
}

private extension View {
    func sidebarControlButtonStyle() -> some View {
        modifier(SidebarControlButtonStyleModifier())
    }

    func sidebarActionButtonStyle() -> some View {
        modifier(SidebarActionButtonStyleModifier())
    }
}

private func formatByteString(_ value: String) -> String {
    guard let bytes = Double(value), bytes > 0 else {
        return ""
    }

    let units = ["B", "KB", "MB", "GB"]
    var size = bytes
    var index = 0
    while size >= 1024, index < units.count - 1 {
        size /= 1024
        index += 1
    }

    return String(format: index == 0 ? "%.0f %@" : "%.1f %@", size, units[index])
}

private struct SettingsNavigationContext {
    var canGoBack = false
    var canGoForward = false
    var goBack: () -> Void = {}
    var goForward: () -> Void = {}
}

private struct SettingsNavigationContextKey: EnvironmentKey {
    static let defaultValue = SettingsNavigationContext()
}

private extension EnvironmentValues {
    var settingsNavigationContext: SettingsNavigationContext {
        get { self[SettingsNavigationContextKey.self] }
        set { self[SettingsNavigationContextKey.self] = newValue }
    }
}

struct SettingsRootView: View {
    @State private var tab: SettingsTab = .account
    @State private var backStack: [SettingsTab] = []
    @State private var forwardStack: [SettingsTab] = []
    @State private var isHistoryNavigation = false

    var body: some View {
        NavigationSplitView {
            List(SettingsTab.allCases, selection: $tab) { item in
                Label(item.title, systemImage: item.systemImage)
                    .tag(item)
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 230, ideal: 250, max: 270)
            .toolbar(removing: .sidebarToggle)
        } detail: {
            switch tab {
            case .account: AccountSettingsView()
            case .storage: StorageSettingsView()
            case .language: LanguageSettingsView()
            case .about: AboutSettingsView()
            }
        }
        .navigationSplitViewStyle(.balanced)
        .toolbar(removing: .title)
        .background(SettingsWindowConfigurator())
        .environment(\.settingsNavigationContext,
                      SettingsNavigationContext(canGoBack: !backStack.isEmpty,
                                                canGoForward: !forwardStack.isEmpty,
                                                goBack: goBack,
                                                goForward: goForward))
        .onChange(of: tab) { oldValue, newValue in
            guard oldValue != newValue else { return }
            if isHistoryNavigation {
                isHistoryNavigation = false
                return
            }
            backStack.append(oldValue)
            forwardStack.removeAll()
        }
        .frame(minWidth: 860, minHeight: 560)
        .onAppear(perform: resetToAccount)
        .onDisappear(perform: resetToAccount)
    }

    private func resetToAccount() {
        if tab != .account {
            isHistoryNavigation = true
            tab = .account
        }
        backStack.removeAll()
        forwardStack.removeAll()
    }

    private func goBack() {
        guard let previous = backStack.popLast() else { return }
        forwardStack.append(tab)
        isHistoryNavigation = true
        tab = previous
    }

    private func goForward() {
        guard let next = forwardStack.popLast() else { return }
        backStack.append(tab)
        isHistoryNavigation = true
        tab = next
    }
}

private struct SettingsPill: View {
    let title: String
    var isSelected: Bool = false

    var body: some View {
        Text(title)
            .font(.caption.weight(.semibold))
            .lineLimit(1)
            .minimumScaleFactor(0.82)
            .truncationMode(.tail)
            .foregroundStyle(isSelected ? Color.white.opacity(0.86) : Color.secondary)
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(isSelected ? Color.white.opacity(0.18) : Color.primary.opacity(0.08), in: Capsule())
            .layoutPriority(-1)
    }
}

private struct SettingsContentPane<Accessory: View, Content: View>: View {
    @Environment(\.settingsNavigationContext) private var navigationContext
    let tab: SettingsTab
    private let accessory: Accessory
    private let content: Content

    init(tab: SettingsTab,
         @ViewBuilder accessory: () -> Accessory,
         @ViewBuilder content: () -> Content) {
        self.tab = tab
        self.accessory = accessory()
        self.content = content()
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                content
            }
            .padding(.top, 18)
            .padding(.bottom, 24)
            .padding(.horizontal, 20)
            .frame(maxWidth: 860, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .scrollIndicators(.visible)
        .scrollEdgeEffectStyle(.soft, for: .top)
        .toolbar(removing: .title)
        .toolbar { settingsToolbar }
    }

    @ToolbarContentBuilder
    private var settingsToolbar: some ToolbarContent {
        ToolbarItem(placement: .navigation) {
            HStack(spacing: 12) {
                SettingsNavigationButtons(context: navigationContext)

                Text(tab.title)
                    .font(.system(size: 15, weight: .semibold))
                    .lineLimit(1)
                    .fixedSize()
            }
        }
        .sharedBackgroundVisibility(.hidden)

        if Accessory.self != EmptyView.self {
            ToolbarItem(placement: .primaryAction) {
                accessory
            }
        }
    }
}

private struct SettingsNavigationButtons: View {
    let context: SettingsNavigationContext

    var body: some View {
        HStack(spacing: 0) {
            navButton(systemImage: "chevron.left",
                      isEnabled: context.canGoBack,
                      action: context.goBack)

            Rectangle()
                .fill(Color(nsColor: .separatorColor).opacity(0.22))
                .frame(width: 1, height: 17)

            navButton(systemImage: "chevron.right",
                      isEnabled: context.canGoForward,
                      action: context.goForward)
        }
        .frame(width: 72, height: 32)
        .glassEffect(.regular, in: Capsule())
    }

    private func navButton(systemImage: String, isEnabled: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: systemImage)
                .font(.system(size: 17, weight: .medium))
                .frame(width: 35, height: 32)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(isEnabled ? Color.primary.opacity(0.72) : Color.secondary.opacity(0.28))
        .disabled(!isEnabled)
    }
}

private extension SettingsContentPane where Accessory == EmptyView {
    init(tab: SettingsTab, @ViewBuilder content: () -> Content) {
        self.init(tab: tab, accessory: { EmptyView() }, content: content)
    }
}

private struct SettingsGroupBox<Content: View>: View {
    @Environment(\.colorScheme) private var colorScheme
    let title: String?
    private let content: Content

    init(_ title: String? = nil, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let title {
                Text(title)
                    .font(.headline)
                    .padding(.leading, 2)
            }

            VStack(spacing: 0) {
                content
            }
            .frame(maxWidth: .infinity)
            .background {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(groupFill)
            }
            .overlay {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(groupStroke, lineWidth: 1)
            }
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
    }

    private var groupFill: Color {
        colorScheme == .dark ? Color.white.opacity(0.07) : Color.black.opacity(0.035)
    }

    private var groupStroke: Color {
        colorScheme == .dark ? Color.white.opacity(0.08) : Color.black.opacity(0.035)
    }
}

private struct SettingsGroupDivider: View {
    var body: some View {
        Divider()
            .padding(.leading, 18)
    }
}

private struct SettingsAccountActionsBar: View {
    let onEdit: () -> Void
    let onDelete: () -> Void
    var isSelected: Bool = false

    var body: some View {
        HStack(spacing: 0) {
            SettingsAccountActionButton(systemImage: "square.and.pencil",
                                        tint: .secondary,
                                        size: 13,
                                        yOffset: -1,
                                        help: String(localized: "编辑账户"),
                                        action: onEdit)
            SettingsAccountActionButton(systemImage: "trash",
                                        tint: .red,
                                        size: 13.5,
                                        help: String(localized: "删除账户"),
                                        action: onDelete)
        }
        .padding(2.5)
        .glassEffect(.regular.tint(isSelected ? Color.white.opacity(0.18) : Color.clear), in: Capsule())
    }
}

private struct SettingsAccountActionButton: View {
    let systemImage: String
    let tint: Color
    let size: CGFloat
    var yOffset: CGFloat = 0
    let help: String
    let action: () -> Void
    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            Image(systemName: systemImage)
                .font(.system(size: size, weight: .regular))
                .foregroundStyle(tint)
                .offset(y: yOffset)
                .frame(width: 26, height: 26)
                .background(isHovered ? tint.opacity(0.13) : Color.clear, in: Circle())
                .contentShape(Circle())
        }
        .buttonStyle(StablePressButtonStyle())
        .onHover { hovering in
            withAnimation(.snappy(duration: 0.16)) {
                isHovered = hovering
            }
        }
    }
}

enum AccountEditorContext: Identifiable {
    case new
    case edit(StoredAccount)
    var id: String {
        switch self {
        case .new: return "new"
        case .edit(let account): return account.id.uuidString
        }
    }
    var account: StoredAccount? {
        if case .edit(let account) = self { return account }
        return nil
    }
}

struct AccountSettingsView: View {
    @EnvironmentObject private var accountStore: AccountStore
    @State private var editor: AccountEditorContext?
    @State private var accountPendingDeletion: StoredAccount?
    @State private var deviceGUID = DeviceGUIDStore.current()

    var body: some View {
        SettingsContentPane(tab: .account) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 9) {
                    Text(String(localized: "Apple 账户"))
                        .font(.headline)
                        .padding(.leading, 2)

                    Button {
                        editor = .new
                    } label: {
                        Image(systemName: "plus")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundStyle(Color.accentColor)
                            .frame(width: 26, height: 26)
                            .contentShape(Circle())
                    }
                    .buttonStyle(StablePressButtonStyle())
                    .glassEffect(.regular.interactive(), in: Circle())

                    Spacer(minLength: 0)
                }

                SettingsGroupBox {
                    if accountStore.accounts.isEmpty {
                        AccountSettingsEmptyState()
                    } else {
                        ForEach(Array(accountStore.accounts.enumerated()), id: \.element.id) { index, account in
                            AccountSettingsRow(account: account,
                                               onEdit: { editor = .edit(account) },
                                               onDelete: { accountPendingDeletion = account })
                            if index < accountStore.accounts.count - 1 {
                                SettingsGroupDivider()
                            }
                        }
                    }
                }
            }

            SettingsGroupBox(String(localized: "设备")) {
                SettingsDeviceGUIDRow(deviceGUID: deviceGUID)
            }

            SettingsGroupBox(String(localized: "安全")) {
                HStack(spacing: 14) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(String(localized: "本地凭据保护"))
                            .font(.callout.weight(.semibold))
                        Text(String(localized: "Apple 账户密码存储在 macOS Keychain 中，本机只保存账户名称和地区等非敏感设置。"))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    Spacer()

                    Label(String(localized: "使用 Keychain 保护"), systemImage: "lock.shield")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 10)
            }
        }
        .onAppear {
            deviceGUID = DeviceGUIDStore.current()
        }
        .sheet(item: $editor) { context in
            AccountEditorView(context: context)
                .environmentObject(accountStore)
        }
        .confirmationDialog(
            String(localized: "确认删除这个 Apple 账户？"),
            isPresented: Binding(
                get: { accountPendingDeletion != nil },
                set: { if !$0 { accountPendingDeletion = nil } }
            ),
            presenting: accountPendingDeletion
        ) { account in
            Button(String(localized: "确认删除"), role: .destructive) {
                accountStore.delete(account)
                accountPendingDeletion = nil
            }
            Button(String(localized: "取消"), role: .cancel) {
                accountPendingDeletion = nil
            }
        } message: { account in
            Text(String(localized: "将从本机移除 \(account.displayLabel)。"))
        }
    }
}

private struct SettingsDeviceGUIDRow: View {
    let deviceGUID: String
    @State private var copied = false

    var body: some View {
        HStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 3) {
                Text(String(localized: "设备 GUID"))
                    .font(.callout.weight(.semibold))
                Text(String(localized: "用于 Apple Store Services 登录和下载请求。"))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 16)

            Text(deviceGUID)
                .font(.system(.callout, design: .monospaced).weight(.medium))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)

            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(deviceGUID, forType: .string)
                copied = true
                Task {
                    try? await Task.sleep(nanoseconds: 1_400_000_000)
                    await MainActor.run { copied = false }
                }
            } label: {
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    .frame(width: 18, height: 18)
            }
            .buttonStyle(.borderless)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 10)
    }
}

private struct AccountSettingsEmptyState: View {
    var body: some View {
        Text(String(localized: "添加 Apple 账户以登录。"))
            .font(.callout)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .center)
            .padding(.horizontal, 18)
            .padding(.vertical, 18)
    }
}

struct AccountSettingsRow: View {
    @EnvironmentObject private var accountStore: AccountStore
    let account: StoredAccount
    let onEdit: () -> Void
    let onDelete: () -> Void

    var body: some View {
        let isSelected = account.id == accountStore.selectedAccountID
        HStack(alignment: .center, spacing: 12) {
            HStack(spacing: 8) {
                SettingsPill(title: account.countryName, isSelected: isSelected)

                Text(account.displayLabel)
                    .font(.body)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .foregroundStyle(isSelected ? Color.white : Color.primary)
                    .layoutPriority(1)
            }
            .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
            .onTapGesture {
                accountStore.select(account)
            }

            Spacer(minLength: 12)

            SettingsAccountActionsBar(onEdit: onEdit, onDelete: onDelete, isSelected: isSelected)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 5)
        .frame(minHeight: 38)
        .background(isSelected ? Color(nsColor: .selectedContentBackgroundColor) : Color.clear)
    }
}

private struct AccountEditorInputRow: View {
    enum Kind {
        case text
        case secure
        case code
    }

    let title: String
    let prompt: String
    let kind: Kind
    @Binding var text: String
    var onSubmit: (() -> Void)?
    @FocusState private var isFocused: Bool

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            Text(title)
                .font(.callout.weight(.medium))
                .foregroundStyle(.primary)
                .frame(width: 92, alignment: .leading)

            ZStack(alignment: .leading) {
                input
                    .textFieldStyle(.plain)
                    .font(.body)
                    .lineLimit(1)
                    .frame(maxWidth: .infinity)
                    .frame(height: 22, alignment: .center)
                    .focused($isFocused)

                if text.isEmpty {
                    Text(prompt)
                        .font(.body)
                        .foregroundStyle(Color(nsColor: .placeholderTextColor))
                        .allowsHitTesting(false)
                }
            }
            .padding(.horizontal, 10)
            .frame(height: 32)
            .frame(maxWidth: .infinity)
            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(isFocused ? Color.accentColor.opacity(0.65) : Color(nsColor: .separatorColor).opacity(0.28),
                            lineWidth: isFocused ? 1.5 : 1)
            }
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 10)
        .frame(minHeight: 52)
    }

    @ViewBuilder
    private var input: some View {
        switch kind {
        case .text:
            TextField("", text: $text)
                .textContentType(.username)
                .onSubmit { onSubmit?() }
        case .secure:
            SecureField("", text: $text)
                .onSubmit { onSubmit?() }
        case .code:
            TextField("", text: $text)
                .textContentType(.oneTimeCode)
                .onSubmit { onSubmit?() }
        }
    }
}

private struct AccountEditorDivider: View {
    var body: some View {
        Divider()
            .padding(.leading, 128)
    }
}

private struct AccountEditorBoxStyle: ViewModifier {
    func body(content: Content) -> some View {
        content
            .background {
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .fill(Color.black.opacity(0.035))
            }
            .overlay {
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .stroke(Color(nsColor: .separatorColor).opacity(0.18), lineWidth: 1)
            }
            .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}

struct AccountEditorView: View {
    @EnvironmentObject private var accountStore: AccountStore
    @Environment(\.dismiss) private var dismiss
    @AppStorage("catalogCountry") private var selectedCountryCode = "cn"
    let context: AccountEditorContext

    @State private var email = ""
    @State private var password = ""
    @State private var code = ""

    private var editingID: UUID? { context.account?.id }
    private var canSubmit: Bool {
        !email.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !password.isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(editingID == nil ? String(localized: "添加 Apple 账户") : String(localized: "编辑 Apple 账户"))
                .font(.title3.weight(.semibold))

            VStack(spacing: 0) {
                AccountEditorInputRow(title: String(localized: "Apple 账户"),
                                      prompt: "name@example.com",
                                      kind: .text,
                                      text: $email)

                AccountEditorDivider()

                AccountEditorInputRow(title: String(localized: "密码"),
                                      prompt: String(localized: "Apple 账户密码"),
                                      kind: .secure,
                                      text: $password)
            }
            .modifier(AccountEditorBoxStyle())

            if accountStore.needsCode {
                VStack(alignment: .leading, spacing: 8) {
                    Text(String(localized: "验证码已发送至你的受信任 Apple 设备，请输入双重认证验证码。"))
                        .font(.callout.weight(.semibold))
                        .fixedSize(horizontal: false, vertical: true)

                    VStack(spacing: 0) {
                        AccountEditorInputRow(title: String(localized: "验证码"),
                                              prompt: String(localized: "验证码"),
                                              kind: .code,
                                              text: $code,
                                              onSubmit: { accountStore.submitCode(code) })
                    }
                    .modifier(AccountEditorBoxStyle())
                }
            } else {
                Text(String(localized: "保存前会先登录验证，并在需要时要求双重认证验证码。"))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if accountStore.isValidating {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(accountStore.validationMessage.isEmpty ? String(localized: "正在验证…") : accountStore.validationMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else if !accountStore.needsCode && !accountStore.validationMessage.isEmpty {
                Text(accountStore.validationMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                Spacer()
                Button(String(localized: "取消")) {
                    accountStore.cancelValidation()
                    dismiss()
                }
                if accountStore.needsCode {
                    Button(String(localized: "继续")) { accountStore.submitCode(code) }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                        .disabled(code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                } else {
                    Button(String(localized: "保存")) {
                        accountStore.validate(email: email, password: password,
                                              editingID: editingID, fallbackCountry: selectedCountryCode)
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSubmit || accountStore.isValidating)
                }
            }
        }
        .padding(24)
        .frame(width: 520)
        .onAppear {
            accountStore.validationMessage = ""
            accountStore.needsCode = false
            if let account = context.account {
                email = account.appleAccount
                password = account.password
                if password.isEmpty {
                    password = (try? accountStore.password(for: account)) ?? ""
                }
            }
        }
        .onChange(of: accountStore.saveTick) { _, _ in dismiss() }
    }
}

struct StorageSettingsView: View {
    @AppStorage("downloadDir") private var downloadDir = ""

    var body: some View {
        SettingsContentPane(tab: .storage) {
            SettingsGroupBox(String(localized: "下载文件")) {
                HStack(alignment: .center, spacing: 16) {
                    Text(String(localized: "保存目录"))
                        .font(.callout.weight(.medium))

                    Spacer()

                    Text(downloadDir.isEmpty ? String(localized: "未设置") : downloadDir)
                        .font(.callout)
                        .foregroundStyle(downloadDir.isEmpty ? Color.secondary : Color.primary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)

                    Button {
                        chooseDir()
                    } label: {
                        Label(String(localized: "选择保存目录"), systemImage: "folder")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 10)
            }
        }
    }

    private func chooseDir() {
        let panel = NSOpenPanel()
        panel.title = String(localized: "选择保存目录")
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = true
        if !downloadDir.isEmpty { panel.directoryURL = URL(fileURLWithPath: downloadDir, isDirectory: true) }
        if panel.runModal() == .OK, let url = panel.url { downloadDir = url.path }
    }
}

struct LanguageSettingsView: View {
    @AppStorage(AppLanguage.overrideKey) private var languageOverride = ""
    @State private var showingRelaunch = false

    var body: some View {
        SettingsContentPane(tab: .language) {
            SettingsGroupBox(String(localized: "显示语言")) {
                HStack(alignment: .center, spacing: 16) {
                    Text(String(localized: "语言"))
                        .font(.callout.weight(.medium))

                    Spacer()

                    HStack {
                        Spacer(minLength: 0)

                        Picker(String(localized: "语言"), selection: $languageOverride) {
                            ForEach(AppLanguage.all) { lang in
                                Text(lang.displayName).tag(lang.code)
                            }
                        }
                        .labelsHidden()
                        .pickerStyle(.menu)
                        .fixedSize(horizontal: true, vertical: false)
                    }
                    .frame(width: 300, alignment: .trailing)
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 12)
            }

            Text(String(localized: "切换语言后需要重新启动 App 才能完全生效。"))
                .font(.callout)
                .foregroundStyle(.secondary)
                .padding(.top, -10)
        }
        .onChange(of: languageOverride) { _, code in
            if code.isEmpty {
                UserDefaults.standard.removeObject(forKey: "AppleLanguages")
            } else {
                UserDefaults.standard.set([code], forKey: "AppleLanguages")
            }
            showingRelaunch = true
        }
        .alert(String(localized: "需要重新启动"), isPresented: $showingRelaunch) {
            Button(String(localized: "立即重启")) { relaunchApp() }
            Button(String(localized: "稍后"), role: .cancel) { }
        } message: {
            Text(String(localized: "语言更改将在重新启动 App 后完全生效。"))
        }
    }

    private func relaunchApp() {
        let url = Bundle.main.bundleURL
        let config = NSWorkspace.OpenConfiguration()
        config.createsNewApplicationInstance = true
        NSWorkspace.shared.openApplication(at: url, configuration: config) { _, _ in
            DispatchQueue.main.async { NSApp.terminate(nil) }
        }
    }
}

struct AboutSettingsView: View {
    @EnvironmentObject private var updateManager: AppUpdateManager
    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "26.7"
    }
    private let thirdParty: [(String, String)] = [
        ("axios", "https://www.npmjs.com/package/axios"),
        ("archiver", "https://www.npmjs.com/package/archiver"),
        ("dotenv", "https://www.npmjs.com/package/dotenv"),
        ("fetch-cookie", "https://www.npmjs.com/package/fetch-cookie"),
        ("getmac", "https://www.npmjs.com/package/getmac"),
        ("node-stream-zip", "https://www.npmjs.com/package/node-stream-zip"),
        ("p-queue", "https://www.npmjs.com/package/p-queue"),
        ("plist", "https://www.npmjs.com/package/plist"),
        ("tough-cookie", "https://www.npmjs.com/package/tough-cookie"),
        ("axios-cookiejar-support", "https://www.npmjs.com/package/axios-cookiejar-support"),
    ]

    var body: some View {
        SettingsContentPane(tab: .about) {
            SettingsGroupBox {
                HStack(spacing: 14) {
                    Image(nsImage: NSApp.applicationIconImage)
                        .resizable()
                        .frame(width: 52, height: 52)
                        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))

                    VStack(alignment: .leading, spacing: 5) {
                        Text(appDisplayName)
                            .font(.title3)
                        Text(verbatim: "v\(appVersion)")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }

                    Spacer()
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 11)
            }

            SettingsGroupBox(String(localized: "应用")) {
                HStack {
                    Text(String(localized: "版本"))
                    Spacer()
                    Text(appVersion)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                .font(.callout)
                .padding(.horizontal, 18)
                .padding(.vertical, 10)

                SettingsGroupDivider()

                CheckForUpdatesSettingsRow(updater: updateManager.updater)

                SettingsGroupDivider()

                SettingsLinkRow(title: String(localized: "制作人"),
                                subtitle: "EEliberto",
                                url: "https://github.com/EEliberto/IPA-Download")
            }

            SettingsGroupBox(String(localized: "开源项目")) {
                SettingsLinkRow(title: "ipatool.ts",
                                subtitle: String(localized: "下载与购买逻辑参考"),
                                url: "https://github.com/beerpiss/ipatool.ts")
                SettingsGroupDivider()
                SettingsLinkRow(title: "Asspp",
                                subtitle: String(localized: "下载与购买逻辑参考"),
                                url: "https://github.com/Lakr233/Asspp")
                SettingsGroupDivider()
                SettingsLinkRow(title: "SideStore · apple-private-apis",
                                subtitle: String(localized: "登录流程参考（GSA / SRP / 2FA / Anisette）"),
                                url: "https://github.com/SideStore/apple-private-apis")
                SettingsGroupDivider()
                SettingsLinkRow(title: "Node.js",
                                subtitle: String(localized: "内置运行时"),
                                url: "https://nodejs.org")
                SettingsGroupDivider()
                SettingsLinkRow(title: "Sparkle",
                                subtitle: String(localized: "自动更新框架"),
                                url: "https://sparkle-project.org")
            }

            SettingsGroupBox(String(localized: "第三方依赖")) {
                ForEach(Array(thirdParty.enumerated()), id: \.element.0) { index, item in
                    SettingsLinkRow(title: item.0,
                                    subtitle: String(localized: "npm 组件"),
                                    url: item.1)
                    if index < thirdParty.count - 1 {
                        SettingsGroupDivider()
                    }
                }
            }

            SettingsGroupBox(String(localized: "历史版本来源")) {
                SettingsLinkRow(title: "Timbrd", subtitle: String(localized: "历史版本数据源"), url: "https://timbrd.com")
                SettingsGroupDivider()
                SettingsLinkRow(title: "Agzy", subtitle: String(localized: "历史版本数据源"), url: "https://app.agzy.cn")
                SettingsGroupDivider()
                SettingsLinkRow(title: "Bilin", subtitle: String(localized: "历史版本数据源"), url: "https://apis.bilin.eu.org")
            }
        }
    }
}

private struct SettingsLinkRow: View {
    let title: String
    let subtitle: String
    let url: String

    var body: some View {
        if let link = URL(string: url) {
            Link(destination: link) {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(title)
                            .foregroundStyle(.primary)
                        Text(subtitle)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    Image(systemName: "arrow.up.right")
                        .foregroundStyle(.tertiary)
                }
                .contentShape(Rectangle())
                .padding(.horizontal, 18)
                .padding(.vertical, 10)
            }
            .buttonStyle(.plain)
        }
    }
}

private struct SettingsActionRow: View {
    let title: String
    let subtitle: String
    let systemImage: String
    var isEnabled = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(title)
                        .foregroundStyle(.primary)
                    Text(subtitle)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Image(systemName: systemImage)
                    .foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
            .padding(.horizontal, 18)
            .padding(.vertical, 10)
        }
        .buttonStyle(.plain)
        .disabled(!isEnabled)
    }
}

final class AppUpdateManager: ObservableObject {
    let updaterController: SPUStandardUpdaterController

    init() {
        updaterController = SPUStandardUpdaterController(startingUpdater: true,
                                                         updaterDelegate: nil,
                                                         userDriverDelegate: nil)
    }

    var updater: SPUUpdater {
        updaterController.updater
    }
}

final class CheckForUpdatesViewModel: ObservableObject {
    @Published var canCheckForUpdates = false

    init(updater: SPUUpdater) {
        updater.publisher(for: \.canCheckForUpdates)
            .receive(on: RunLoop.main)
            .assign(to: &$canCheckForUpdates)
    }
}

private struct CheckForUpdatesMenuItem: View {
    @ObservedObject private var viewModel: CheckForUpdatesViewModel
    private let updater: SPUUpdater

    init(updater: SPUUpdater) {
        self.updater = updater
        viewModel = CheckForUpdatesViewModel(updater: updater)
    }

    var body: some View {
        Button(String(localized: "检查更新…")) {
            updater.checkForUpdates()
        }
        .disabled(!viewModel.canCheckForUpdates)
    }
}

private struct CheckForUpdatesSettingsRow: View {
    @ObservedObject private var viewModel: CheckForUpdatesViewModel
    private let updater: SPUUpdater

    init(updater: SPUUpdater) {
        self.updater = updater
        viewModel = CheckForUpdatesViewModel(updater: updater)
    }

    var body: some View {
        SettingsActionRow(title: String(localized: "检查更新"),
                          subtitle: String(localized: "从 GitHub 检查 Pastel 新版本。"),
                          systemImage: "arrow.clockwise",
                          isEnabled: viewModel.canCheckForUpdates) {
            updater.checkForUpdates()
        }
    }
}

private struct FocusReleaseClickMonitor: NSViewRepresentable {
    @Binding var isEditing: Bool

    func makeCoordinator() -> Coordinator {
        Coordinator(isEditing: $isEditing)
    }

    func makeNSView(context: Context) -> NSView {
        let view = NSView(frame: .zero)
        context.coordinator.installIfNeeded()
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        context.coordinator.isEditing = $isEditing
    }

    static func dismantleNSView(_ nsView: NSView, coordinator: Coordinator) {
        coordinator.uninstall()
    }

    final class Coordinator {
        var isEditing: Binding<Bool>
        private var monitor: Any?

        init(isEditing: Binding<Bool>) {
            self.isEditing = isEditing
        }

        func installIfNeeded() {
            guard monitor == nil else { return }
            monitor = NSEvent.addLocalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] event in
                self?.handle(event)
                return event
            }
        }

        func uninstall() {
            if let monitor {
                NSEvent.removeMonitor(monitor)
            }
            monitor = nil
        }

        private func handle(_ event: NSEvent) {
            guard isEditing.wrappedValue, let window = event.window else { return }
            guard let firstResponder = window.firstResponder as? NSTextView else { return }

            if click(event, isInside: firstResponder, in: window) {
                return
            }

            DispatchQueue.main.async {
                self.isEditing.wrappedValue = false
                if window.firstResponder === firstResponder {
                    window.makeFirstResponder(nil)
                }
            }
        }

        private func click(_ event: NSEvent, isInside textView: NSTextView, in window: NSWindow) -> Bool {
            guard let superview = textView.superview else { return false }
            let fieldRect = superview.convert(textView.frame, to: nil).insetBy(dx: -10, dy: -10)
            return fieldRect.contains(event.locationInWindow)
        }
    }
}

private final class KeyboardShortcutState {
    static let shared = KeyboardShortcutState()
    var isTextEditing = false

    private init() {}
}

struct PastelSettingsCommands: Commands {
    @Environment(\.openWindow) private var openWindow
    let updateManager: AppUpdateManager

    var body: some Commands {
        CommandGroup(replacing: .appSettings) {
            Button(String(localized: "设置…")) {
                openWindow(id: "settings")
            }
            .keyboardShortcut(",", modifiers: .command)
        }

        CommandMenu(String(localized: "操作")) {
            Button(String(localized: "刷新")) {
                NotificationCenter.default.post(name: .pastelRefreshActivePanel, object: nil)
            }
            .keyboardShortcut("r", modifiers: .command)
        }

        CommandGroup(after: .appInfo) {
            CheckForUpdatesMenuItem(updater: updateManager.updater)
        }
    }
}

@main
struct PastelApp: App {
    @StateObject private var accountStore = AccountStore()
    @StateObject private var updateManager = AppUpdateManager()

    init() {
        ApplicationKeyboardShortcutInterceptor.install()
    }

    var body: some Scene {
        Window(appDisplayName, id: "main") {
            ContentView()
                .environmentObject(accountStore)
                .environmentObject(updateManager)
        }
        .windowStyle(.hiddenTitleBar)
        .windowBackgroundDragBehavior(.disabled)
        .windowResizability(.contentMinSize)
        .defaultSize(width: 1240, height: 820)
        .commands {
            PastelSettingsCommands(updateManager: updateManager)
        }

        Window(String(localized: "设置"), id: "settings") {
            SettingsRootView()
                .environmentObject(accountStore)
                .environmentObject(updateManager)
                .frame(minWidth: 860, minHeight: 560)
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 920, height: 620)
        .windowResizability(.contentMinSize)
        .restorationBehavior(.disabled)
    }
}
