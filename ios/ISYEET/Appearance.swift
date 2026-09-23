import SwiftUI

enum AppAppearance: String, CaseIterable, Identifiable, Sendable {
    case messaging
    case terminal

    var id: String { rawValue }
    var title: String { self == .messaging ? "Messaging" : "Terminal / IRC" }
    var colorScheme: ColorScheme? { self == .terminal ? .dark : nil }

    func font(_ style: Font.TextStyle) -> Font {
        .system(style, design: self == .terminal ? .monospaced : .default)
    }

    var background: Color {
        self == .terminal ? Color(red: 0.02, green: 0.05, blue: 0.035) : Color(.systemGroupedBackground)
    }

    var surface: Color {
        self == .terminal ? Color(red: 0.035, green: 0.09, blue: 0.055) : Color(.secondarySystemGroupedBackground)
    }

    var primary: Color {
        self == .terminal ? Color(red: 0.57, green: 0.97, blue: 0.68) : .primary
    }

    var secondary: Color {
        self == .terminal ? Color(red: 0.48, green: 0.72, blue: 0.55) : .secondary
    }

    var accent: Color {
        self == .terminal ? Color(red: 0.38, green: 0.95, blue: 0.57) : .blue
    }

    var warning: Color {
        self == .terminal ? Color(red: 1, green: 0.79, blue: 0.38) : .red
    }

    var incomingBackground: Color {
        self == .terminal ? surface : Color(.secondarySystemGroupedBackground)
    }

    var outgoingBackground: Color {
        self == .terminal ? Color(red: 0.06, green: 0.19, blue: 0.10) : Color(red: 0, green: 0.35, blue: 0.78)
    }

    var outgoingText: Color { self == .terminal ? primary : .white }
}

private struct AppearanceKey: EnvironmentKey {
    static let defaultValue = AppAppearance.messaging
}

extension EnvironmentValues {
    var appearance: AppAppearance {
        get { self[AppearanceKey.self] }
        set { self[AppearanceKey.self] = newValue }
    }
}

struct AppearanceView: View {
    @Binding var selection: String
    @Environment(\.appearance) private var appearance
    @Environment(\.dismiss) private var dismiss

    private var selected: AppAppearance { AppAppearance(rawValue: selection) ?? .messaging }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Style", selection: $selection) {
                        ForEach(AppAppearance.allCases) { option in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(verbatim: option.title)
                                    .font(appearance.font(.body))
                                Text(option == .messaging ? "Familiar layout. Follows your device's light or dark setting." : "Green text, a dark background, and a monospaced font.")
                                    .font(appearance.font(.caption))
                                    .foregroundStyle(appearance.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            .tag(option.rawValue)
                        }
                    }
                    .pickerStyle(.inline)
                } footer: {
                    Text("Saved on this device. Your messages and encryption stay the same.")
                        .font(appearance.font(.footnote))
                        .foregroundStyle(appearance.secondary)
                }
                .listRowBackground(appearance.surface)

                Section("Preview") {
                    VStack(alignment: .leading, spacing: 16) {
                        Text(selected == .terminal ? "<contact> Just text." : "Just text.")
                            .font(selected.font(.body))
                            .foregroundStyle(selected.primary)
                            .padding(12)
                            .background(selected.incomingBackground, in: RoundedRectangle(cornerRadius: selected == .terminal ? 2 : 16))
                        HStack {
                            Spacer(minLength: 16)
                            Text(selected == .terminal ? "<you> Encrypted end to end." : "Encrypted end to end.")
                                .font(selected.font(.body))
                                .foregroundStyle(selected.outgoingText)
                                .padding(12)
                                .background(selected.outgoingBackground, in: RoundedRectangle(cornerRadius: selected == .terminal ? 2 : 16))
                        }
                    }
                    .padding(.vertical, 8)
                    .listRowBackground(selected.background)
                    .accessibilityLabel("Example of the selected appearance")
                }
            }
            .font(appearance.font(.body))
            .foregroundStyle(appearance.primary)
            .scrollContentBackground(.hidden)
            .background(appearance.background)
            .tint(appearance.accent)
            .navigationTitle("Appearance")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Close") { dismiss() }
                }
            }
        }
        .preferredColorScheme(appearance.colorScheme)
    }
}
