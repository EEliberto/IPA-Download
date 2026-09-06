import Observation
import SwiftUI

@MainActor
@Observable
final class VersionHistoryFeatureState {
    var selectedVersion: VersionRecord?
    var selectedVersionIDs: Set<String> = []
    var lastSelectedVersionID: String?
    var noUpdateSelections: [String: Bool] = [:]
    var appleVersionFetchNeedsAcquisition = false
}

struct SourceProviderCapsule: View {
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
    let onSignIn: () -> Void
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
            DownloadErrorIndicator(
                message: errorMessage,
                requiresSignIn: downloadRequiresRelogin(from: errorLog),
                retry: onDownload,
                signIn: onSignIn
            )
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
