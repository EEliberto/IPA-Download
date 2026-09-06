import Observation
import SwiftUI

@MainActor
@Observable
final class TaskLogFeatureState {
    var manualAppID = ""
    var manualVersionID = ""
    var manualNoUpdate = false
    var manualLatestDownloadedPath: String?
    var manualLatestDownloadedJobID: String?
}

struct DownloadErrorIndicator: View {
    let message: String
    let requiresSignIn: Bool
    let retry: () -> Void
    let signIn: () -> Void
    @State private var isShowingError = false

    var body: some View {
        HStack(spacing: 4) {
            Button {
                isShowingError.toggle()
            } label: {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(.yellow)
                    .frame(width: requiresSignIn ? 30 : 58, height: 26)
                    .contentShape(Capsule())
            }
            .buttonStyle(StablePressButtonStyle())
            .glassEffect(.regular.tint(Color.yellow.opacity(0.18)).interactive(), in: Capsule())
            .accessibilityLabel(String(localized: "查看下载错误"))
            .help(message)
            .popover(isPresented: $isShowingError, arrowEdge: .trailing) {
                VStack(alignment: .leading, spacing: 14) {
                    Label(String(localized: "下载失败"), systemImage: "exclamationmark.triangle.fill")
                        .font(.headline)
                        .foregroundStyle(.primary)
                        .symbolRenderingMode(.multicolor)

                    Text(message)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)

                    HStack {
                        Spacer()
                        if requiresSignIn {
                            Button(String(localized: "登录")) {
                                isShowingError = false
                                signIn()
                            }
                        }
                        Button(String(localized: "重试下载")) {
                            isShowingError = false
                            retry()
                        }
                        .keyboardShortcut(.defaultAction)
                    }
                }
                .padding(16)
                .frame(width: 320)
            }

            if requiresSignIn {
                Button {
                    isShowingError = false
                    signIn()
                } label: {
                    Label(String(localized: "登录"), systemImage: "person.crop.circle")
                        .font(.caption.weight(.semibold))
                        .lineLimit(1)
                        .minimumScaleFactor(0.75)
                        .frame(width: 62, height: 26)
                        .contentShape(Capsule())
                }
                .buttonStyle(StablePressButtonStyle())
                .foregroundStyle(Color.accentColor)
                .glassEffect(.regular.interactive(), in: Capsule())
                .help(message)
            }
        }
    }
}
