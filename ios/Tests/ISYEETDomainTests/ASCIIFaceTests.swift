import Testing
@testable import ISYEETDomain

@Test func asciiFaceCatalogIsExactlyEightLiteralPrintableChoices() throws {
    #expect(ASCIIFace.allCases.map(\.name) == ["Happy", "Smile", "Wink", "Surprised", "Sad", "Love", "Celebrate", "Cat"])
    #expect(ASCIIFace.allCases.map(\.text) == ["(^_^)", ":-)", ";-)", "(o_o)", ":(", "<3", "\\o/", "=^.^="])
    #expect(Set(ASCIIFace.allCases.map(\.id)).count == 8)
    for face in ASCIIFace.allCases {
        try MessageSafety.validate(face.text)
        #expect(try face.appending(to: "") == face.text)
    }
    #expect(Array(ASCIIFace.celebrate.text.utf8) == [0x5c, 0x6f, 0x2f])
}

@Test func asciiFaceInsertionPreservesLiteralDraftAndExistingSpaces() throws {
    #expect(try ASCIIFace.smile.appending(to: "hello") == "hello :-)")
    #expect(try ASCIIFace.smile.appending(to: "hello ") == "hello :-)")
    #expect(try ASCIIFace.smile.appending(to: "  hello   ") == "  hello   :-)")
    #expect(try ASCIIFace.happy.appending(to: " ") == " (^_^)")
    #expect(try ASCIIFace.cat.appending(to: "**literal** <3 \\o/") == "**literal** <3 \\o/ =^.^=")
    #expect(try ASCIIFace.wink.appending(to: ASCIIFace.love.appending(to: "")) == "<3 ;-)")
}

@Test func asciiFaceInsertionCountsTheSeparatorAtTheMessageBoundary() throws {
    for face in ASCIIFace.allCases {
        let maximumDraft = String(repeating: "x", count: MessageSafety.maximumBytes - face.text.utf8.count - 1)
        let result = try face.appending(to: maximumDraft)
        #expect(result.utf8.count == MessageSafety.maximumBytes)
        #expect(result == maximumDraft + " " + face.text)
        #expect(throws: SafetyError.invalidText) { try face.appending(to: maximumDraft + "x") }

        let alreadySeparated = maximumDraft + " "
        #expect(try face.appending(to: alreadySeparated) == alreadySeparated + face.text)
        #expect(throws: SafetyError.invalidText) { try face.appending(to: alreadySeparated + " ") }
    }
}

@Test func asciiFaceInsertionRejectsInvalidDraftWithoutChangingIt() {
    let invalidDrafts = ["hello\n", "\r", "\t", "\0", "\u{1b}[31m", "\u{7f}", "\u{a0}", "caf\u{e9}", "\u{1f642}", String(repeating: "x", count: 1024)]
    for original in invalidDrafts {
        var draft = original
        #expect(throws: SafetyError.invalidText) { draft = try ASCIIFace.happy.appending(to: draft) }
        #expect(draft == original)
    }
}
