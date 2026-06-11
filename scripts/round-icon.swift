// 把「滿版方圖」轉成 macOS 原生風格圖示：
// 自動偵測中央 squircle 內容邊界、裁掉深色外框，套上透明圓角。
//   swift scripts/round-icon.swift <in.png> <out.png> [outSize=1024]
import AppKit
import CoreGraphics

let args = CommandLine.arguments
guard args.count >= 3 else {
    FileHandle.standardError.write(Data("用法: round-icon.swift <in.png> <out.png> [outSize]\n".utf8))
    exit(1)
}
let inPath = args[1], outPath = args[2]
let outSize = args.count >= 4 ? (Int(args[3]) ?? 1024) : 1024

guard let img = NSImage(contentsOfFile: inPath),
      let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
    FileHandle.standardError.write(Data("無法讀取來源圖\n".utf8))
    exit(1)
}
let W = cg.width, H = cg.height
let cs = CGColorSpaceCreateDeviceRGB()
let bpr = W * 4
var px = [UInt8](repeating: 0, count: H * bpr)
// CGContext 為左下原點；偵測與裁切都在同一座標系，避免上下顛倒
let bm = CGImageAlphaInfo.premultipliedLast.rawValue
guard let rc = CGContext(data: &px, width: W, height: H, bitsPerComponent: 8,
                         bytesPerRow: bpr, space: cs, bitmapInfo: bm) else { exit(1) }
rc.draw(cg, in: CGRect(x: 0, y: 0, width: W, height: H))

@inline(__always) func bright(_ x: Int, _ y: Int) -> Int {
    let i = y * bpr + x * 4
    return (Int(px[i]) + Int(px[i+1]) + Int(px[i+2])) / 3
}
// 以四角平均亮度為背景基準
let bg = (bright(2, 2) + bright(W-3, 2) + bright(2, H-3) + bright(W-3, H-3)) / 4
let thr = bg + 22

var minX = W, minY = H, maxX = 0, maxY = 0
for y in 0..<H {
    for x in 0..<W where bright(x, y) > thr {
        if x < minX { minX = x }; if x > maxX { maxX = x }
        if y < minY { minY = y }; if y > maxY { maxY = y }
    }
}
if maxX <= minX || maxY <= minY { minX = 0; minY = 0; maxX = W-1; maxY = H-1 }

// 取正方形、置中、外擴一點點以含住 squircle 暗色描邊
let cx = (minX + maxX) / 2, cy = (minY + maxY) / 2
var half = max(maxX - minX, maxY - minY) / 2
half = Int(Double(half) * 1.03)
let side = Double(half * 2)
let scale = Double(outSize) / side

guard let out = CGContext(data: nil, width: outSize, height: outSize, bitsPerComponent: 8,
                          bytesPerRow: 0, space: cs, bitmapInfo: bm) else { exit(1) }
let rect = CGRect(x: 0, y: 0, width: outSize, height: outSize)
let radius = CGFloat(Double(outSize) * 0.2237)   // Apple 圓角比例
out.addPath(CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil))
out.clip()
// 把來源中 [cx±half, cy±half] 的區域放大填滿輸出
let drawX = (0 - Double(cx - half)) * scale
let drawY = (0 - Double(cy - half)) * scale
out.interpolationQuality = .high
out.draw(cg, in: CGRect(x: drawX, y: drawY, width: Double(W) * scale, height: Double(H) * scale))

guard let result = out.makeImage() else { exit(1) }
let rep = NSBitmapImageRep(cgImage: result)
guard let png = rep.representation(using: .png, properties: [:]) else { exit(1) }
try! png.write(to: URL(fileURLWithPath: outPath))
print("ok bbox=(\(minX),\(minY))-(\(maxX),\(maxY)) bg=\(bg)")
