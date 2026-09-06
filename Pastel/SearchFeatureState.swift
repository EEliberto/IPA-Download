import AppKit
import Observation
import SwiftUI

@MainActor
@Observable
final class SearchFeatureState {
    var hoveredMode: RightPanelMode?
    var selectedApp: AppSearchResult?
    var selectedAppLocalIconPath: String?
    var remoteAppIcons: [String: NSImage] = [:]
    var storefrontReloadTask: Task<Void, Never>?
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

                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(result.artistName)
                        .lineLimit(1)
                        .truncationMode(.tail)

                    if !result.fileSizeText.isEmpty {
                        Spacer(minLength: 8)
                        Text(result.fileSizeText)
                            .lineLimit(1)
                            .fixedSize(horizontal: true, vertical: false)
                    }
                }
                .font(.caption)
                .foregroundStyle(isSelected ? Color.white.opacity(0.78) : Color.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
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
