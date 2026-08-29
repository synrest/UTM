//
// Copyright © 2026 osy. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
//

import Foundation
import Darwin
import Security

enum UTMControlRequest: Codable {
    case list
    case status(identifier: String)
    case start(identifier: String)
    case stop(identifier: String)
    case suspend(identifier: String)
    case resume(identifier: String)

    private enum CodingKeys: String, CodingKey { case command, identifier }
    private enum Command: String, Codable { case list, status, start, stop, suspend, resume }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Command.self, forKey: .command) {
        case .list:
            self = .list
        case .status:
            self = .status(identifier: try container.decode(String.self, forKey: .identifier))
        case .start:
            self = .start(identifier: try container.decode(String.self, forKey: .identifier))
        case .stop:
            self = .stop(identifier: try container.decode(String.self, forKey: .identifier))
        case .suspend:
            self = .suspend(identifier: try container.decode(String.self, forKey: .identifier))
        case .resume:
            self = .resume(identifier: try container.decode(String.self, forKey: .identifier))
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .list:
            try container.encode(Command.list, forKey: .command)
        case .status(let identifier):
            try container.encode(Command.status, forKey: .command)
            try container.encode(identifier, forKey: .identifier)
        case .start(let identifier):
            try container.encode(Command.start, forKey: .command)
            try container.encode(identifier, forKey: .identifier)
        case .stop(let identifier):
            try container.encode(Command.stop, forKey: .command)
            try container.encode(identifier, forKey: .identifier)
        case .suspend(let identifier):
            try container.encode(Command.suspend, forKey: .command)
            try container.encode(identifier, forKey: .identifier)
        case .resume(let identifier):
            try container.encode(Command.resume, forKey: .command)
            try container.encode(identifier, forKey: .identifier)
        }
    }
}

enum UTMControlLaunchOptions {
    static let autoStartIntentFileName = "utmctl-autostart-intent"
}

struct UTMControlLaunchIntent: Codable {
    let processIdentifier: Int32
    let timestamp: TimeInterval
}

struct UTMControlVM: Codable {
    let uuid: String
    let name: String
    let state: String
    let backend: String
    let loaded: Bool

    private enum CodingKeys: String, CodingKey { case uuid, name, state, backend, loaded }

    init(uuid: String, name: String, state: String, backend: String, loaded: Bool) {
        self.uuid = uuid
        self.name = name
        self.state = state
        self.backend = backend
        self.loaded = loaded
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        uuid = try container.decode(String.self, forKey: .uuid)
        name = try container.decode(String.self, forKey: .name)
        state = try container.decode(String.self, forKey: .state)
        backend = try container.decode(String.self, forKey: .backend)
        loaded = try container.decodeIfPresent(Bool.self, forKey: .loaded) ?? true
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(uuid, forKey: .uuid)
        try container.encode(name, forKey: .name)
        try container.encode(state, forKey: .state)
        try container.encode(backend, forKey: .backend)
        try container.encode(loaded, forKey: .loaded)
    }
}

struct UTMControlResponse: Codable {
    let schema: Int
    let command: String?
    let vms: [UTMControlVM]?
    let vm: UTMControlVM?
    let error: UTMControlError?

    private enum CodingKeys: String, CodingKey { case schema, command, vms, vm, error }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schema, forKey: .schema)
        try container.encodeIfPresent(command, forKey: .command)
        try container.encodeIfPresent(vms, forKey: .vms)
        try container.encodeIfPresent(vm, forKey: .vm)
        try container.encodeIfPresent(error, forKey: .error)
    }

    static func list(_ vms: [UTMControlVM]) -> Self {
        Self(schema: 1, command: "list", vms: vms, vm: nil, error: nil)
    }

    static func status(_ vm: UTMControlVM) -> Self {
        Self(schema: 1, command: "status", vms: nil, vm: vm, error: nil)
    }

    static func operation(_ command: String, _ vm: UTMControlVM) -> Self {
        Self(schema: 1, command: command, vms: nil, vm: vm, error: nil)
    }

    static func failure(_ error: UTMControlError) -> Self {
        Self(schema: 1, command: nil, vms: nil, vm: nil, error: error)
    }
}

struct UTMControlError: Codable {
    let code: String
    let message: String
    let identifier: String?
    let retryable: Bool
}

enum UTMControlTransportError: Error {
    case unavailable
    case protocolError
}

enum UTMControlTransport {
    static let timeout: TimeInterval = 10
    private static let timeoutMilliseconds: Int32 = 10_000
    private static let maximumFrameSize = 1024 * 1024

    static func configure(_ descriptor: Int32) throws {
        var noSigPipe: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw UTMControlTransportError.unavailable
        }
    }

    static func makeNonblocking(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFL, 0)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw UTMControlTransportError.unavailable
        }
    }

    static func writeAll(_ data: Data, to descriptor: Int32, timeout: TimeInterval = UTMControlTransport.timeout) throws {
        let deadline = Date().addingTimeInterval(timeout)
        try data.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.baseAddress else { return }
            var offset = 0
            while offset < bytes.count {
                try wait(for: descriptor, events: Int16(POLLOUT), until: deadline)
                let count = Darwin.write(descriptor, baseAddress.advanced(by: offset), bytes.count - offset)
                if count > 0 {
                    offset += count
                } else if count < 0, errno == EINTR {
                    continue
                } else if count < 0, errno == EAGAIN || errno == EWOULDBLOCK {
                    continue
                } else {
                    throw UTMControlTransportError.unavailable
                }
            }
        }
    }

    static func readFrame(from descriptor: Int32, timeout: TimeInterval = UTMControlTransport.timeout) throws -> Data {
        let deadline = Date().addingTimeInterval(timeout)
        var frame = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            try wait(for: descriptor, events: Int16(POLLIN), until: deadline)
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count == 0 {
                throw UTMControlTransportError.unavailable
            }
            if count < 0 {
                if errno == EINTR { continue }
                throw UTMControlTransportError.unavailable
            }
            frame.append(contentsOf: buffer[0..<count])
            if frame.contains(10) {
                return frame
            }
            if frame.count > maximumFrameSize {
                throw UTMControlTransportError.protocolError
            }
        }
    }

    private static func wait(for descriptor: Int32, events: Int16, until deadline: Date) throws {
        var pollDescriptor = pollfd(fd: descriptor, events: events, revents: 0)
        while true {
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else { throw UTMControlTransportError.unavailable }
            let milliseconds = min(timeoutMilliseconds, max(1, Int32(remaining * 1000)))
            let result = Darwin.poll(&pollDescriptor, 1, milliseconds)
            if result > 0 {
                let errors = Int16(POLLERR | POLLNVAL)
                guard pollDescriptor.revents & errors == 0 else {
                    throw UTMControlTransportError.unavailable
                }
                return
            }
            if result == 0 {
                if deadline.timeIntervalSinceNow > 0 {
                    continue
                }
                throw UTMControlTransportError.unavailable
            }
            if errno != EINTR {
                throw UTMControlTransportError.unavailable
            }
        }
    }
}

enum UTMControlErrorCode {
    static let unavailable = "UTM_UNAVAILABLE"
    static let notFound = "VM_NOT_FOUND"
    static let ambiguous = "AMBIGUOUS_VM_NAME"
    static let protocolError = "PROTOCOL_ERROR"
    static let invalidState = "INVALID_VM_STATE"
    static let vmUnavailable = "VM_UNAVAILABLE"
    static let backendUnavailable = "BACKEND_UNAVAILABLE"
    static let backendFailure = "BACKEND_FAILURE"
    static let operationTimeout = "OPERATION_TIMEOUT"
    static let powerDownTimeout = "POWER_DOWN_TIMEOUT"
}

enum UTMControlSocket {
    static let socketName = "control/utmctl.sock"

    static var applicationGroupIdentifier: String? {
        guard let task = SecTaskCreateFromSelf(nil),
              let groups = SecTaskCopyValueForEntitlement(task, "com.apple.security.application-groups" as CFString, nil) as? [String] else {
            return nil
        }
        return groups.first
    }

    static var launchIntentURL: URL? {
        url?.deletingLastPathComponent().appendingPathComponent(UTMControlLaunchOptions.autoStartIntentFileName)
    }

    static var url: URL? {
        guard let identifier = applicationGroupIdentifier,
              var container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier) else {
            return nil
        }
        if container.lastPathComponent == "Data",
           container.deletingLastPathComponent().lastPathComponent == identifier {
            let library = container.deletingLastPathComponent()
                .deletingLastPathComponent()
                .deletingLastPathComponent()
            let groupContainer = library.appendingPathComponent("Group Containers", isDirectory: true)
                .appendingPathComponent(identifier, isDirectory: true)
            guard FileManager.default.fileExists(atPath: groupContainer.path) else {
                return nil
            }
            container = groupContainer
        }
        return container.appendingPathComponent(socketName)
    }
}

final class UTMControlClient {
    enum ClientError: Error {
        case unavailable
        case protocolError
    }

    func request(_ request: UTMControlRequest, responseTimeout: TimeInterval = UTMControlTransport.timeout) throws -> UTMControlResponse {
        guard let url = UTMControlSocket.url else {
            throw ClientError.unavailable
        }
        let descriptor = try connect(to: url.path)
        defer { close(descriptor) }

        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        var payload = try encoder.encode(request)
        payload.append(10)
        do {
            try UTMControlTransport.writeAll(payload, to: descriptor)
        } catch UTMControlTransportError.protocolError {
            throw ClientError.protocolError
        } catch {
            throw ClientError.unavailable
        }

        let responseData: Data
        do {
            responseData = try UTMControlTransport.readFrame(from: descriptor, timeout: responseTimeout)
        } catch UTMControlTransportError.protocolError {
            throw ClientError.protocolError
        } catch {
            throw ClientError.unavailable
        }
        guard let response = try? decoder.decode(UTMControlResponse.self, from: responseData) else {
            throw ClientError.protocolError
        }
        return response
    }

    private func connect(to path: String) throws -> Int32 {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw ClientError.unavailable }
        do {
            try UTMControlTransport.configure(descriptor)
            try UTMControlTransport.makeNonblocking(descriptor)
        } catch {
            close(descriptor)
            throw ClientError.unavailable
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8) + [0]
        guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            close(descriptor)
            throw ClientError.unavailable
        }
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.initializeMemory(as: UInt8.self, repeating: 0)
            pathBytes.withUnsafeBytes { source in
                destination.copyBytes(from: source)
            }
        }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            close(descriptor)
            throw ClientError.unavailable
        }
        return descriptor
    }
}
