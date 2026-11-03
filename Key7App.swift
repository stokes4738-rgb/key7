import SwiftUI

@main
struct Key7App: App {
    @StateObject private var key = FIDODevice()

    var body: some Scene {
        WindowGroup {
            NavigationView {
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        HStack {
                            Image(systemName: "key.fill")
                                .font(.system(size: 36))
                                .foregroundColor(.mint)
                            VStack(alignment: .leading) {
                                Text("Key7").font(.largeTitle.bold())
                                Text("FIDO2 Bluetooth research prototype")
                                    .font(.subheadline).foregroundColor(.secondary)
                            }
                        }
                        .padding(.top, 12)

                        VStack(alignment: .leading, spacing: 12) {
                            Label(key.advertising ? "Advertising" : "Not advertising",
                                  systemImage: key.advertising ? "antenna.radiowaves.left.and.right" : "antenna.radiowaves.left.and.right.slash")
                                .font(.headline)
                            Text(key.status).font(.callout).fixedSize(horizontal: false, vertical: true)
                            Button(action: { key.setEnabled(!key.advertising) }) {
                                Label(key.advertising ? "Stop key" : "Start key",
                                      systemImage: key.advertising ? "stop.fill" : "play.fill")
                                    .frame(maxWidth: .infinity).padding(13)
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(key.advertising ? .red : .mint)
                        }
                        .padding().background(Color(.secondarySystemGroupedBackground))
                        .cornerRadius(16)

                        HStack(spacing: 12) {
                            metric("Subscribers", value: "\(key.connectedClients)")
                            metric("Credentials", value: "\(key.credentialCount)")
                        }

                        VStack(alignment: .leading, spacing: 8) {
                            Text("Latest request").font(.headline)
                            Text(key.lastOperation).font(.callout).textSelection(.enabled)
                        }
                        .padding().frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(.secondarySystemGroupedBackground)).cornerRadius(16)

                        VStack(alignment: .leading, spacing: 10) {
                            Label("Lab mode only", systemImage: "exclamationmark.shield.fill")
                                .font(.headline).foregroundColor(.orange)
                            Text("Not FIDO certified. Do not enroll important accounts. BLE pairing, platform compatibility, and security require testing. Keep this screen open and the phone unlocked while testing.")
                                .font(.callout)
                            Text("A credential request requires Touch ID or device passcode. Keys are stored in this phone's device-only Keychain.")
                                .font(.callout)
                        }
                        .padding().background(Color(.secondarySystemGroupedBackground)).cornerRadius(16)
                    }
                    .padding()
                }
                .background(Color(.systemGroupedBackground))
                .navigationBarTitleDisplayMode(.inline)
            }
        }
    }

    private func metric(_ title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(value).font(.title.bold())
            Text(title).font(.caption).foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemGroupedBackground))
        .cornerRadius(14)
    }
}
