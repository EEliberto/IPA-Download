import AppKit
import Observation
import SwiftUI

enum DownloadSelectionScope {
    case appGroups
    case versions
}

@MainActor
@Observable
final class DownloadLibraryFeatureState {
    var downloadedFiles: [String: URL] = [:]
    var versionIcons: [String: NSImage] = [:]
    var downloadedVersionIDs: [String: URL] = [:]
    var downloadedItems: [DownloadedItem] = []
    var selectedDownloadedItemID: String?
    var selectedDownloadedItemIDs: Set<String> = []
    var lastSelectedDownloadedItemID: String?
    var selectedDownloadedGroupID: String?
    var selectedDownloadedGroupIDs: Set<String> = []
    var lastSelectedDownloadedGroupID: String?
    var downloadSelectionScope: DownloadSelectionScope = .appGroups
    var downloadSearchQuery = ""
    var expandedGroups: Set<String> = []
    var downloadLibraryRefreshTask: Task<Void, Never>?
    var iconPathsBeingLoaded: Set<String> = []
}

struct DownloadedAppSidebarRow: View {
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

                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(group.developer.isEmpty ? group.bundleId : group.developer)
                        .lineLimit(1)
                        .truncationMode(.tail)
                    Spacer(minLength: 8)
                    Text(String(localized: "\(group.items.count) 个版本"))
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                }
                .font(.caption)
                .foregroundStyle(isSelected ? Color.white.opacity(0.78) : Color.secondary)
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

struct DownloadedVersionHistoryRow: View {
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
