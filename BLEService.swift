import Foundation
import Combine
import CoreBluetooth
import LocalAuthentication
import UIKit

// Bluetooth FIDO CTAP framing. All sizes are bytes, big endian.
struct IncomingFrame {
    private(set) var command: UInt8?
    private(set) var expected = 0
    private(set) var sequence: UInt8 = 0
    private(set) var collected = Data()

    mutating func add(_ packet: Data) -> FrameState {
        let b = Array(packet)
        guard let first = b.first else { return .failure(0x03) }
        if (first & 0x80) != 0 {
            guard b.count >= 3 else { return .failure(0x03) }
            command = first
            expected = Int(b[1]) << 8 | Int(b[2])
            guard expected <= 4096, b.count - 3 <= expected else { return .failure(0x03) }
            collected = Data(b.dropFirst(3))
            sequence = 0
        } else {
            guard command != nil, first == sequence, b.count - 1 <= expected - collected.count else {
                return .failure(0x04) // invalid sequence
            }
            collected.append(contentsOf: b.dropFirst())
            sequence = (sequence &+ 1) & 0x7F
        }
        if collected.count == expected, let finished = command {
            let result = FrameState.complete(finished, collected)
            command = nil; collected = Data(); expected = 0; sequence = 0
            return result
        }
        return .incomplete
    }
}

enum FrameState {
    case incomplete
    case complete(UInt8, Data)
    case failure(UInt8)
}

enum OutgoingFramer {
    static func packets(command: UInt8, payload: Data, chunk: Int) -> [Data] {
        guard chunk >= 4, payload.count <= 65535 else { return [] }
        var result: [Data] = []
        let count = payload.count
        let firstSize = min(count, chunk - 3)
        result.append(Data([command, UInt8(count >> 8), UInt8(count & 0xFF)]) + payload.prefix(firstSize))
        var offset = firstSize
        var index: UInt8 = 0
        while offset < count {
            let length = min(chunk - 1, count - offset)
            result.append(Data([index]) + payload.subdata(in: offset..<(offset + length)))
            offset += length
            index = (index &+ 1) & 0x7F
        }
        return result
    }
}

final class FIDODevice: NSObject, ObservableObject, CBPeripheralManagerDelegate {
    @Published private(set) var status = "Bluetooth is initializing…"
    @Published private(set) var advertising = false
    @Published private(set) var connectedClients = 0
    @Published private(set) var credentialCount = 0
    @Published private(set) var lastOperation = "No requests yet"

    private let engine = Authenticator()
    private var manager: CBPeripheralManager!
    private var wanted = false
    private var startedServices = false
    private var controlPoint: CBMutableCharacteristic?
    private var statusPoint: CBMutableCharacteristic?
    private var revisionPoint: CBMutableCharacteristic?
    private var pointLength: CBMutableCharacteristic?
    private var frameStates: [UUID: IncomingFrame] = [:]
    private var subscribed: [UUID: CBCentral] = [:]
    private var revisions: [UUID: Bool] = [:]
    private var outgoing: [(CBCentral, Data)] = []
    private var busy = false
    private var keepalive: Timer?

    private let fidoServiceUUID = CBUUID(string: "FFFD")
    private let cmdUUID = CBUUID(string: "F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB")
    private let statusUUID = CBUUID(string: "F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB")
    private let lengthUUID = CBUUID(string: "F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB")
    private let revisionUUID = CBUUID(string: "F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB")

    override init() {
        super.init()
        credentialCount = (try? engine.vault.all().count) ?? 0
        manager = CBPeripheralManager(delegate: self, queue: .main)
    }

    func setEnabled(_ enable: Bool) {
        wanted = enable
        if enable {
            UIApplication.shared.isIdleTimerDisabled = true
            guard manager.state == .poweredOn else {
                status = "Enable Bluetooth and open Key7 again"
                return
            }
            publish()
        } else {
            keepalive?.invalidate(); keepalive = nil
            manager.stopAdvertising()
            manager.removeAllServices()
            startedServices = false
            advertising = false
            busy = false
            frameStates.removeAll(); revisions.removeAll()
            outgoing.removeAll(); subscribed.removeAll()
            connectedClients = 0
            UIApplication.shared.isIdleTimerDisabled = false
            status = "Stopped. The key is not advertising."
        }
    }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        switch peripheral.state {
        case .poweredOn:
            status = "Bluetooth on. Tap Start key to advertise."
            if wanted { publish() }
        case .poweredOff: status = "Bluetooth is off"
        case .unauthorized: status = "Bluetooth permission denied"
        case .unsupported: status = "BLE peripheral mode not supported"
        default: status = "Bluetooth unavailable: \(peripheral.state.rawValue)"
        }
    }

    private func publish() {
        guard !startedServices, manager.state == .poweredOn else { return }
        startedServices = true
        controlPoint = CBMutableCharacteristic(type: cmdUUID,
            properties: [.write], value: nil, permissions: [.writeEncryptionRequired])
        statusPoint = CBMutableCharacteristic(type: statusUUID,
            properties: [.notify, .notifyEncryptionRequired], value: nil, permissions: [])
        pointLength = CBMutableCharacteristic(type: lengthUUID,
            properties: [.read], value: Data([0, 20]), permissions: [.readable])
        revisionPoint = CBMutableCharacteristic(type: revisionUUID,
            properties: [.read, .write], value: nil,
            permissions: [.readable, .writeEncryptionRequired])
        let service = CBMutableService(type: fidoServiceUUID, primary: true)
        service.characteristics = [controlPoint!, statusPoint!, pointLength!, revisionPoint!]
        manager.add(service)

        // The device-information service helps GATT inspection tools identify the prototype.
        let deviceInfo = CBMutableService(type: CBUUID(string: "180A"), primary: true)
        func infoChar(_ uuid: String, _ text: String) -> CBMutableCharacteristic {
            CBMutableCharacteristic(type: CBUUID(string: uuid), properties: [.read],
                                    value: Data(text.utf8), permissions: [.readable])
        }
        deviceInfo.characteristics = [infoChar("2A29", "Key7 research"),
                                      infoChar("2A24", "iPhone 7 Plus"),
                                      infoChar("2A26", "0.1")]
        manager.add(deviceInfo)
        status = "Publishing FIDO Bluetooth service…"
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        if let error = error {
            status = "Cannot publish GATT service: \(error.localizedDescription)"
            return
        }
        guard wanted, service.uuid == fidoServiceUUID else { return }
        manager.startAdvertising([
            CBAdvertisementDataLocalNameKey: "Key7-FIDO-Lab",
            CBAdvertisementDataServiceUUIDsKey: [fidoServiceUUID]
        ])
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if let error = error {
            status = "Bluetooth advertisement failed: \(error.localizedDescription)"
            advertising = false
        } else {
            advertising = true
            status = "Advertising FIDO service FFFD. Keep Key7 open and unlocked."
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral,
                           didSubscribeTo characteristic: CBCharacteristic) {
        guard characteristic.uuid == statusUUID else { return }
        subscribed[central.identifier] = central
        connectedClients = subscribed.count
        lastOperation = "Client subscribed: \(central.identifier.uuidString.prefix(8))"
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral,
                           didUnsubscribeFrom characteristic: CBCharacteristic) {
        guard characteristic.uuid == statusUUID else { return }
        subscribed.removeValue(forKey: central.identifier)
        frameStates.removeValue(forKey: central.identifier)
        revisions.removeValue(forKey: central.identifier)
        connectedClients = subscribed.count
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
        if request.characteristic.uuid == revisionUUID {
            guard request.offset == 0 else { peripheral.respond(to: request, withResult: .invalidOffset); return }
            request.value = Data([0x20]) // FIDO2 revision bit
            peripheral.respond(to: request, withResult: .success)
        } else if request.characteristic.uuid == lengthUUID {
            guard request.offset <= 2 else { peripheral.respond(to: request, withResult: .invalidOffset); return }
            request.value = Data([0x00, 0x14]).dropFirst(request.offset)
            peripheral.respond(to: request, withResult: .success)
        } else {
            peripheral.respond(to: request, withResult: .readNotPermitted)
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            guard wanted else { peripheral.respond(to: request, withResult: .unlikelyError); continue }
            if request.characteristic.uuid == revisionUUID {
                guard request.offset == 0, request.value == Data([0x20]) else {
                    peripheral.respond(to: request, withResult: .invalidAttributeValueLength)
                    continue
                }
                revisions[request.central.identifier] = true
                peripheral.respond(to: request, withResult: .success)
            } else if request.characteristic.uuid == cmdUUID {
                guard request.offset == 0, let data = request.value,
                      !data.isEmpty, data.count <= 20 else {
                    peripheral.respond(to: request, withResult: .invalidAttributeValueLength)
                    continue
                }
                peripheral.respond(to: request, withResult: .success)
                receive(data, from: request.central)
            } else {
                peripheral.respond(to: request, withResult: .writeNotPermitted)
            }
        }
    }

    private func receive(_ packet: Data, from central: CBCentral) {
        guard subscribed[central.identifier] != nil else { return }
        guard revisions[central.identifier] == true else {
            send(0xBF, Data([0x02]), to: central)
            return
        }
        var state = frameStates[central.identifier] ?? IncomingFrame()
        switch state.add(packet) {
        case .incomplete:
            frameStates[central.identifier] = state
        case .failure(let code):
            frameStates.removeValue(forKey: central.identifier)
            send(0xBF, Data([code]), to: central)
        case .complete(let command, let data):
            frameStates.removeValue(forKey: central.identifier)
            switch command {
            case 0x81: send(0x81, data, to: central) // PING echo
            case 0xBE:
                // Cancellation of an in-progress LocalAuthentication prompt is not yet wired.
                lastOperation = "Cancel requested (not supported during Touch ID prompt)"
            case 0x83:
                if busy { send(0xBF, Data([0x06]), to: central); return }
                busy = true
                lastOperation = "CTAP2 command 0x\(String(format: "%02X", data.first ?? 0))"
                // Timer keeps desktop clients from timing out during Touch ID/passcode UI.
                engine.process(data, needsApproval: { [weak self] prompt, reply in
                    guard let self = self else { reply(false); return }
                    self.lastOperation = prompt
                    self.keepalive = Timer.scheduledTimer(withTimeInterval: 0.9, repeats: true) { [weak self] _ in
                        self?.send(0x82, Data([0x02]), to: central)
                    }
                    let context = LAContext()
                    context.localizedCancelTitle = "Deny"
                    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: prompt) { allowed, _ in
                        DispatchQueue.main.async { reply(allowed) }
                    }
                }, completion: { [weak self] response in
                    DispatchQueue.main.async {
                        guard let self = self else { return }
                        self.keepalive?.invalidate(); self.keepalive = nil
                        self.busy = false
                        self.credentialCount = (try? self.engine.vault.all().count) ?? self.credentialCount
                        self.lastOperation = "CTAP reply status 0x\(String(format: "%02X", response.first ?? 0xFF))"
                        self.send(0x83, response, to: central)
                    }
                })
            default: send(0xBF, Data([0x01]), to: central)
            }
        }
    }

    private func send(_ command: UInt8, _ payload: Data, to central: CBCentral) {
        // 20-byte notifications for maximum compatibility with unnegotiated ATT MTU.
        for fragment in OutgoingFramer.packets(command: command, payload: payload, chunk: 20) {
            outgoing.append((central, fragment))
        }
        flush()
    }

    private func flush() {
        guard let characteristic = statusPoint else { return }
        while !outgoing.isEmpty {
            let (central, fragment) = outgoing[0]
            if subscribed[central.identifier] == nil { outgoing.removeFirst(); continue }
            if !manager.updateValue(fragment, for: characteristic, onSubscribedCentrals: [central]) {
                return // Wait for peripheralManagerIsReady(toUpdateSubscribers:)
            }
            outgoing.removeFirst()
        }
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) { flush() }
}
