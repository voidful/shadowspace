import Foundation
import AppKit
import CoreImage

/// 匯入來源的解析：shadowspace:// URL 分派與剪貼簿 QR Code 解碼。
/// 與 AppState 分離以便單元測試 URL 分派邏輯，並把 CoreImage 依賴收攏在一處。
enum ImportService {

    /// shadowspace:// URL 的解析結果。
    enum URLImport: Equatable {
        case notOurs                // 不是我們的 scheme，靜默忽略
        case unrecognized           // 是我們的 scheme 但取不出內容
        case payload(String)        // 取出的匯入內容（分享連結或訂閱網址）
    }

    /// 解析 shadowspace://import?url=<訂閱網址> 或 ?text=<分享連結，可多行>；
    /// 後備：shadowspace://import/<百分比編碼內容>。純函式，可測。
    static func classifyURL(_ url: URL) -> URLImport {
        guard url.scheme?.lowercased() == "shadowspace" else { return .notOurs }
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        if let payload = comps?.queryItems?.first(where: { $0.name == "url" || $0.name == "text" })?.value,
           !payload.isEmpty {
            return .payload(payload)
        }
        let tail = ((comps?.host == "import" ? "" : (comps?.host ?? "")) + (comps?.path ?? ""))
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let decoded = (tail.removingPercentEncoding ?? tail).trimmingCharacters(in: .whitespacesAndNewlines)
        return decoded.isEmpty ? .unrecognized : .payload(decoded)
    }

    /// AppKit 剪貼簿讀取留在 MainActor，先轉成可安全送往背景工作的資料。
    static func qrImageDataFromClipboard() -> Data? {
        guard let image = NSPasteboard.general.readObjects(forClasses: [NSImage.self])?.first as? NSImage,
              let tiff = image.tiffRepresentation else { return nil }
        return tiff
    }

    /// CoreImage 偵測可能需要明顯 CPU 時間，呼叫端可把這段送到背景執行。
    static func qrPayloads(imageData: Data) -> [String] {
        guard let ci = CIImage(data: imageData) else { return [] }
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil,
                                  options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        return (detector?.features(in: ci) ?? [])
            .compactMap { ($0 as? CIQRCodeFeature)?.messageString }
            .filter { !$0.isEmpty }
    }
}
