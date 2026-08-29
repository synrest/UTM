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

struct UTMControlVM: Codable {
    let uuid: String
    let name: String
    let state: String
    let backend: String
    let loaded: Bool?

    private enum CodingKeys: String, CodingKey { case uuid, name, state, backend, loaded }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(uuid, forKey: .uuid)
        try container.encode(name, forKey: .name)
        try container.encode(state, forKey: .state)
        try container.encode(backend, forKey: .backend)
        try container.encodeIfPresent(loaded, forKey: .loaded)
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

enum UTMControlErrorCode {
    static let unavailable = "UTM_UNAVAILABLE"
    static let notFound = "VM_NOT_FOUND"
    static let ambiguous = "AMBIGUOUS_VM_NAME"
    static let protocolError = "PROTOCOL_ERROR"
    static let invalidState = "INVALID_VM_STATE"
    static let vmUnavailable = "VM_UNAVAILABLE"
    static let backendFailure = "BACKEND_FAILURE"
    static let powerDownTimeout = "POWER_DOWN_TIMEOUT"
}

enum UTMControlSocket {
    static let socketName = "control/utmctl.sock"

    static var url: URL? {
        guard let task = SecTaskCreateFromSelf(nil),
              let groups = SecTaskCopyValueForEntitlement(task, "com.apple.security.application-groups" as CFString, nil) as? [String],
              let identifier = groups.first,
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

    func request(_ request: UTMControlRequest) throws -> UTMControlResponse {
        guard let url = UTMControlSocket.url else {
            throw ClientError.unavailable
        }
        let descriptor = try connect(to: url.path)
        defer { close(descriptor) }

        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        var payload = try encoder.encode(request)
        payload.append(10)
        try payload.withUnsafeBytes { bytes in
            guard write(descriptor, bytes.baseAddress, bytes.count) == bytes.count else {
                throw ClientError.unavailable
            }
        }

        var responseData = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = read(descriptor, &buffer, buffer.count)
            if count <= 0 { break }
            responseData.append(contentsOf: buffer[0..<count])
        }
        guard let response = try? decoder.decode(UTMControlResponse.self, from: responseData) else {
            throw ClientError.protocolError
        }
        return response
    }

    private func connect(to path: String) throws -> Int32 {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw ClientError.unavailable }
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
