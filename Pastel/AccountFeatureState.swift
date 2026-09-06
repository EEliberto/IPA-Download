import Observation
import SwiftUI

@MainActor
@Observable
final class AccountFeatureState {
    var pendingVerificationCode = ""
    var showingVerificationPrompt = false
    var pendingCodeJobID: String?
    var saveMessage = ""
    var didLoadCredentials = false
}

struct AccountSelectionButton: View {
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
