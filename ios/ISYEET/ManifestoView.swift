import SwiftUI

private struct ManifestoContent: Decodable {
    struct Section: Decodable {
        let heading: String
        let paragraphs: [String]
    }

    let dispatch: String
    let cabin: String
    let title: String
    let subtitle: String
    let introduction: [String]
    let sections: [Section]
    let closing: [String]

    static let bundled: ManifestoContent? = {
        guard let url = Bundle.main.url(forResource: "Manifesto", withExtension: "json"),
              let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(ManifestoContent.self, from: data)
    }()
}

struct ManifestoView: View {
    @Environment(\.appearance) private var appearance
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                if let content = ManifestoContent.bundled {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 28) {
                            VStack(alignment: .leading, spacing: 20) {
                                Text(verbatim: content.dispatch)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(appearance.secondary)
                                ScrollView(.horizontal) {
                                    Text(verbatim: content.cabin)
                                        .font(.system(size: 12, design: .monospaced))
                                        .fixedSize()
                                }
                                .accessibilityElement(children: .ignore)
                                .accessibilityLabel("An ASCII cabin between pine trees")
                                Text(verbatim: content.title)
                                    .font(.system(.largeTitle, design: .monospaced).bold())
                                    .accessibilityAddTraits(.isHeader)
                                Text(verbatim: content.subtitle)
                                    .font(.system(.subheadline, design: .monospaced))
                                    .foregroundStyle(appearance.secondary)
                            }
                            Divider()
                            paragraphs(content.introduction)
                            ForEach(content.sections.indices, id: \.self) { index in
                                let section = content.sections[index]
                                VStack(alignment: .leading, spacing: 16) {
                                    Text(verbatim: section.heading)
                                        .font(.system(.headline, design: .monospaced))
                                        .accessibilityAddTraits(.isHeader)
                                    paragraphs(section.paragraphs)
                                }
                            }
                            Divider()
                            paragraphs(content.closing)
                                .foregroundStyle(appearance.secondary)
                        }
                        .frame(maxWidth: 640, alignment: .leading)
                        .padding(24)
                        .frame(maxWidth: .infinity)
                        .textSelection(.enabled)
                    }
                    .accessibilityIdentifier("manifestoReader")
                } else {
                    ContentUnavailableView("Manifesto unavailable", systemImage: "book.closed",
                                           description: Text("The manifesto could not be opened."))
                }
            }
            .font(.system(.body, design: .monospaced))
            .foregroundStyle(appearance.primary)
            .background(appearance.background)
            .navigationTitle("Manifesto")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(appearance.background, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .tint(appearance.accent)
        .preferredColorScheme(appearance.colorScheme)
    }

    private func paragraphs(_ values: [String]) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            ForEach(values.indices, id: \.self) { index in
                Text(verbatim: values[index])
                    .lineSpacing(5)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
