#!/usr/bin/env swift
// Recreates the existing website wordmark and colors as an opaque iOS icon.
// Run from the repository root: swift scripts/generate-app-icon.swift
import AppKit
import Foundation
import ImageIO
import UniformTypeIdentifiers

let side = 1024
let bitmap = CGContext(data: nil, width: side, height: side, bitsPerComponent: 8,
    bytesPerRow: side * 4, space: CGColorSpace(name: CGColorSpace.sRGB)!,
    bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
let context = NSGraphicsContext(cgContext: bitmap, flipped: false)
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = context
NSColor(srgbRed: 215 / 255, green: 1, blue: 63 / 255, alpha: 1).setFill()
NSRect(x: 0, y: 0, width: side, height: side).fill()
let mark = "isyeet_" as NSString
let attributes: [NSAttributedString.Key: Any] = [
    .font: NSFont(name: "Menlo-Bold", size: 182)!,
    .foregroundColor: NSColor(srgbRed: 20 / 255, green: 21 / 255, blue: 19 / 255, alpha: 1)
]
let size = mark.size(withAttributes: attributes)
mark.draw(at: NSPoint(x: (CGFloat(side) - size.width) / 2, y: (CGFloat(side) - size.height) / 2), withAttributes: attributes)
NSGraphicsContext.restoreGraphicsState()
let output = URL(fileURLWithPath: "ISYEET/Assets.xcassets/AppIcon.appiconset/AppIcon.png")
let destination = CGImageDestinationCreateWithURL(output as CFURL, UTType.png.identifier as CFString, 1, nil)!
CGImageDestinationAddImage(destination, bitmap.makeImage()!, nil)
guard CGImageDestinationFinalize(destination) else { fatalError("Could not write app icon") }
print("Generated opaque 1024 x 1024 AppIcon.png")
