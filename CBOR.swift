import Foundation

// Minimal, bounded CBOR subset used by CTAP2. No third-party packages.
indirect enum CBOR {
    case unsigned(UInt64)
    case negative(Int64) // An actual negative integer, not encoded n.
    case bytes(Data)
    case text(String)
    case array([CBOR])
    case map([(CBOR, CBOR)])
    case bool(Bool)
    case null

    subscript(_ number: UInt64) -> CBOR? {
        guard case .map(let pairs) = self else { return nil }
        for (key, value) in pairs {
            if case .unsigned(let n) = key, n == number { return value }
        }
        return nil
    }

    subscript(_ name: String) -> CBOR? {
        guard case .map(let pairs) = self else { return nil }
        for (key, value) in pairs {
            if case .text(let n) = key, n == name { return value }
        }
        return nil
    }

    var data: Data? { if case .bytes(let d) = self { return d }; return nil }
    var string: String? { if case .text(let s) = self { return s }; return nil }
    var arrayItems: [CBOR]? { if case .array(let a) = self { return a }; return nil }
    var boolValue: Bool? { if case .bool(let b) = self { return b }; return nil }
    var intValue: Int64? {
        switch self {
        case .unsigned(let u): return u <= UInt64(Int64.max) ? Int64(u) : nil
        case .negative(let n): return n
        default: return nil
        }
    }

    func encoded() -> Data {
        switch self {
        case .unsigned(let value): return CBOR.head(0, value)
        case .negative(let value): return CBOR.head(1, UInt64(-1 - value))
        case .bytes(let bytes): return CBOR.head(2, UInt64(bytes.count)) + bytes
        case .text(let string):
            let bytes = Data(string.utf8)
            return CBOR.head(3, UInt64(bytes.count)) + bytes
        case .array(let items):
            return items.reduce(CBOR.head(4, UInt64(items.count))) { $0 + $1.encoded() }
        case .map(let entries):
            // CTAP2 canonical order: serialized key length, then lexicographic bytes.
            let sorted = entries.map { ($0.0.encoded(), $0.1.encoded()) }.sorted {
                if $0.0.count != $1.0.count { return $0.0.count < $1.0.count }
                return $0.0.lexicographicallyPrecedes($1.0)
            }
            return sorted.reduce(CBOR.head(5, UInt64(sorted.count))) { $0 + $1.0 + $1.1 }
        case .bool(let value): return Data([value ? 0xF5 : 0xF4])
        case .null: return Data([0xF6])
        }
    }

    private static func head(_ major: UInt8, _ length: UInt64) -> Data {
        let top = major << 5
        if length < 24 { return Data([top | UInt8(length)]) }
        if length <= 0xFF { return Data([top | 24, UInt8(length)]) }
        if length <= 0xFFFF {
            return Data([top | 25, UInt8(length >> 8), UInt8(length & 0xFF)])
        }
        if length <= 0xFFFF_FFFF {
            return Data([top | 26, UInt8((length >> 24) & 0xFF), UInt8((length >> 16) & 0xFF), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)])
        }
        return Data([top | 27]) + Data((0..<8).reversed().map { UInt8((length >> (8 * $0)) & 0xFF) })
    }

    static func decode(_ input: Data) -> CBOR? {
        guard input.count <= 8192 else { return nil }
        let bytes = Array(input)
        var offset = 0
        func readByte() -> UInt8? {
            guard offset < bytes.count else { return nil }
            let b = bytes[offset]
            offset += 1
            return b
        }
        func readNumber(_ ai: UInt8) -> UInt64? {
            if ai < 24 { return UInt64(ai) }
            let width: Int
            switch ai {
            case 24: width = 1
            case 25: width = 2
            case 26: width = 4
            case 27: width = 8
            default: return nil // no indefinite lengths
            }
            guard width <= bytes.count - offset else { return nil }
            var result: UInt64 = 0
            for _ in 0..<width { result = (result << 8) | UInt64(bytes[offset]); offset += 1 }
            return result
        }
        func parse(_ depth: Int) -> CBOR? {
            guard depth <= 20, let initial = readByte() else { return nil }
            let major = initial >> 5, ai = initial & 31
            if major == 7 {
                switch ai { case 20: return .bool(false); case 21: return .bool(true); case 22: return .null; default: return nil }
            }
            guard let length = readNumber(ai) else { return nil }
            switch major {
            case 0: return .unsigned(length)
            case 1:
                guard length <= UInt64(Int64.max) else { return nil }
                return .negative(-1 - Int64(length))
            case 2, 3:
                guard length <= UInt64(bytes.count - offset) else { return nil }
                let size = Int(length)
                let chunk = Data(bytes[offset..<(offset + size)])
                offset += size
                if major == 2 { return .bytes(chunk) }
                guard let string = String(data: chunk, encoding: .utf8) else { return nil }
                return .text(string)
            case 4:
                guard length <= 128 else { return nil }
                var values: [CBOR] = []
                for _ in 0..<Int(length) {
                    guard let element = parse(depth + 1) else { return nil }
                    values.append(element)
                }
                return .array(values)
            case 5:
                guard length <= 128 else { return nil }
                var entries: [(CBOR, CBOR)] = []
                for _ in 0..<Int(length) {
                    guard let key = parse(depth + 1), let value = parse(depth + 1) else { return nil }
                    entries.append((key, value))
                }
                return .map(entries)
            default: return nil
            }
        }
        guard let value = parse(0), offset == bytes.count else { return nil }
        return value
    }
}
