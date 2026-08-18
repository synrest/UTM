//
// Copyright © 2020 osy. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

import SwiftUI
import AppIntents

struct UTMApp: App {
    let data: UTMData
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate: AppDelegate
    @AppStorage("HideDockIcon") private var isDockIconHidden: Bool = false
    @AppStorage("ShowMenuIcon") private var isMenuIconShown: Bool = false

    init() {
        let data = UTMData()
        self.data = data
        appDelegate.data = data
        if #available(macOS 13, *) {
            AppDependencyManager.shared.add(dependency: data)
        }
    }

    @ViewBuilder
    var homeWindow: some View {
        ContentView {
            await appDelegate.waitForApplicationStartup()
        }.environmentObject(data)
            .onReceive(.vmSessionError) { notification in
                if let message = notification.userInfo?["Message"] as? String {
                    data.showErrorAlert(message: message)
                }
            }
    }
    
    @SceneBuilder
    var oldBody: some Scene {
        WindowGroup {
            homeWindow
        }.commands {
            VMCommands()
        }
        Settings {
            SettingsView()
        }
    }
    
    @available(macOS 13, *)
    @SceneBuilder
    var newBody: some Scene {
        Window("UTM Library", id: "home") {
            homeWindow
                .navigationTitle("UTM")
                .background(WindowReader { window in
                    appDelegate.registerInteractiveWindow(window, isHomeWindow: true)
                })
        }.commands {
            VMCommands()
        }
        Settings {
            SettingsView().background(WindowReader { window in
                appDelegate.registerInteractiveWindow(window)
            })
        }
        UTMMenuBarExtraScene(data: data)
            .onChange(of: isMenuIconShown) { isVisible in
                appDelegate.menuBarExtraVisibilityDidChange(isVisible)
            }
        Window("UTM Server", id: "server") {
            UTMServerView()
                .environmentObject(data.remoteServer.state)
                .background(WindowReader { window in
                    appDelegate.registerInteractiveWindow(window)
                })
        }
    }

    @available(macOS 15, *)
    @SceneBuilder
    var newestBody: some Scene {
        Window("UTM Library", id: "home") {
            homeWindow
                .navigationTitle("UTM")
                .background(WindowReader { window in
                    appDelegate.registerInteractiveWindow(window, isHomeWindow: true)
                })
        }.commands {
            VMCommands()
        }
        .defaultLaunchBehavior(isDockIconHidden && isMenuIconShown ? .suppressed : .automatic)
        .restorationBehavior(isDockIconHidden && isMenuIconShown ? .disabled : .automatic)
        Settings {
            SettingsView().background(WindowReader { window in
                appDelegate.registerInteractiveWindow(window)
            })
        }
        UTMMenuBarExtraScene(data: data)
            .onChange(of: isMenuIconShown) { isVisible in
                appDelegate.menuBarExtraVisibilityDidChange(isVisible)
            }
        Window("UTM Server", id: "server") {
            UTMServerView()
                .environmentObject(data.remoteServer.state)
                .background(WindowReader { window in
                    appDelegate.registerInteractiveWindow(window)
                })
        }
    }

    @available(macOS 13, *)
    var modernBody: some Scene {
        if #available(macOS 15, *) {
            return newestBody
        } else {
            return newBody
        }
    }
    
    // HACK: SwiftUI doesn't provide if-statement support in SceneBuilder
    var body: some Scene {
        if #available(macOS 13, *) {
            return modernBody
        } else {
            return oldBody
        }
    }
    
}

private struct WindowReader: NSViewRepresentable {
    let onWindowChange: (NSWindow) -> Void

    func makeNSView(context: Context) -> WindowReaderView {
        let view = WindowReaderView()
        view.onWindowChange = onWindowChange
        return view
    }

    func updateNSView(_ nsView: WindowReaderView, context: Context) {
        nsView.onWindowChange = onWindowChange
    }
}

private class WindowReaderView: NSView {
    var onWindowChange: ((NSWindow) -> Void)?

    override func viewWillMove(toWindow newWindow: NSWindow?) {
        if let newWindow = newWindow {
            onWindowChange?(newWindow)
        }
        super.viewWillMove(toWindow: newWindow)
    }
}
