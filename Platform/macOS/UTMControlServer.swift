import Foundation

@MainActor
final class UTMControlServer {
    private let data: UTMData
    private let startupTask: Task<Void, Never>
    private let descriptor: Int32
    private let source: DispatchSourceRead
    private let socketPath: String

    init(data: UTMData, startupTask: Task<Void, Never>) throws {
        self.data = data
        self.startupTask = startupTask
        guard let url = UTMControlSocket.url else { throw ServerError.unavailable() }
        self.socketPath = url.path
        logger.debug("Native control socket path: \(url.path)")
        let directory = url.deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        } catch {
            throw ServerError.unavailable("create directory \(directory.path): \(error.localizedDescription)")
        }
        try Self.removeStaleSocket(at: url.path)

        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw ServerError.unavailable("socket: \(Self.posixError())") }
        self.descriptor = descriptor

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(url.path.utf8) + [0]
        guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            close(descriptor)
            throw ServerError.unavailable("socket path is too long")
        }
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.initializeMemory(as: UInt8.self, repeating: 0)
            pathBytes.withUnsafeBytes { source in destination.copyBytes(from: source) }
        }
        let bindResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0, Darwin.listen(descriptor, 8) == 0 else {
            let error = Self.posixError()
            close(descriptor)
            throw ServerError.unavailable("bind/listen \(url.path): \(error)")
        }
        guard chmod(url.path, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
            let error = Self.posixError()
            close(descriptor)
            unlink(url.path)
            throw ServerError.unavailable("chmod \(url.path): \(error)")
        }

        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: .global(qos: .userInitiated))
        self.source = source
        source.setEventHandler { [weak self] in self?.acceptConnections() }
        source.setCancelHandler { close(descriptor) }
        source.resume()
    }

    deinit {
        source.cancel()
        unlink(socketPath)
    }

    private func acceptConnections() {
        while true {
            let client = accept(descriptor, nil, nil)
            guard client >= 0 else { return }
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                Self.handle(client: client, server: self)
            }
        }
    }

    nonisolated private static func handle(client: Int32, server: UTMControlServer?) {
        var requestData = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while !requestData.contains(10) {
            let count = read(client, &buffer, buffer.count)
            if count <= 0 {
                close(client)
                return
            }
            requestData.append(contentsOf: buffer[0..<count])
            if requestData.count > 1024 * 1024 {
                close(client)
                return
            }
        }
        guard let server else {
            close(client)
            return
        }
        Task { @MainActor in
            defer { close(client) }
            let response = await server.response(for: requestData)
            guard let encoded = try? JSONEncoder().encode(response) else { return }
            var output = encoded
            output.append(10)
            _ = output.withUnsafeBytes { write(client, $0.baseAddress, $0.count) }
        }
    }

    private func response(for requestData: Data) async -> UTMControlResponse {
        await startupTask.value
        guard let request = try? JSONDecoder().decode(UTMControlRequest.self, from: requestData) else {
            return .failure(UTMControlError(code: UTMControlErrorCode.protocolError,
                                            message: "Invalid control request.", identifier: nil, retryable: false))
        }
        switch request {
        case .list:
            return .list(data.virtualMachines.map(record))
        case .status(let identifier):
            do {
                return .status(record(try resolve(identifier)))
            } catch let error as ControlLookupError {
                return .failure(error.controlError(identifier: identifier))
            } catch {
                return .failure(UTMControlError(code: UTMControlErrorCode.notFound,
                                                message: "Virtual machine not found.", identifier: identifier, retryable: false))
            }
        }
    }

    private func resolve(_ identifier: String) throws -> VMData {
        if let uuid = UUID(uuidString: identifier), let vm = data.virtualMachines.first(where: { $0.id == uuid }) {
            return vm
        }
        let matches = data.virtualMachines.filter { $0.detailsTitleLabel == identifier }
        if matches.count > 1 { throw ControlLookupError.ambiguous }
        guard let vm = matches.first else { throw ControlLookupError.notFound }
        return vm
    }

    private func record(_ vm: VMData) -> UTMControlVM {
        let wrapped = vm.wrapped
        let backend: String
        if wrapped is UTMQemuVirtualMachine { backend = "qemu" }
        else if wrapped is UTMAppleVirtualMachine { backend = "apple" }
        else { backend = "unavailable" }
        return UTMControlVM(uuid: vm.id.uuidString, name: vm.detailsTitleLabel,
                            state: vm.state.controlName, backend: backend, loaded: vm.isLoaded)
    }

    private static func removeStaleSocket(at path: String) throws {
        var info = stat()
        if lstat(path, &info) != 0 {
            guard errno == ENOENT else { throw ServerError.unavailable("inspect socket path \(path): \(posixError())") }
            return
        }
        guard (info.st_mode & S_IFMT) == S_IFSOCK else { throw ServerError.unavailable("refusing to replace non-socket path \(path)") }
        let probe = socket(AF_UNIX, SOCK_STREAM, 0)
        if probe >= 0 {
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            let bytes = Array(path.utf8) + [0]
            withUnsafeMutableBytes(of: &address.sun_path) { destination in
                bytes.withUnsafeBytes { destination.copyBytes(from: $0) }
            }
            let result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(probe, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            close(probe)
            if result == 0 { throw ServerError.unavailable("control socket is already active at \(path)") }
        }
        guard unlink(path) == 0 else { throw ServerError.unavailable("remove stale socket \(path): \(posixError())") }
    }

    private static func posixError() -> String {
        String(cString: strerror(errno))
    }

    enum ServerError: Error, LocalizedError {
        case unavailable(String = "native control server unavailable")

        var errorDescription: String? {
            switch self {
            case .unavailable(let message): return message
            }
        }
    }
    enum ControlLookupError: Error {
        case notFound, ambiguous
        func controlError(identifier: String) -> UTMControlError {
            switch self {
            case .notFound:
                return UTMControlError(code: UTMControlErrorCode.notFound, message: "Virtual machine not found.", identifier: identifier, retryable: false)
            case .ambiguous:
                return UTMControlError(code: UTMControlErrorCode.ambiguous, message: "More than one virtual machine has this exact name.", identifier: identifier, retryable: false)
            }
        }
    }
}

private extension UTMVirtualMachineState {
    var controlName: String {
        switch self {
        case .stopped: return "stopped"
        case .starting: return "starting"
        case .started: return "started"
        case .pausing: return "pausing"
        case .paused: return "paused"
        case .resuming: return "resuming"
        case .saving: return "saving"
        case .restoring: return "restoring"
        case .stopping: return "stopping"
        }
    }
}
