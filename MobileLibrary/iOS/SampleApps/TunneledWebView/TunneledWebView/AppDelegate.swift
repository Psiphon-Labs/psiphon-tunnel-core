//
//  AppDelegate.swift
//  TunneledWebView
//
/*
 Licensed under Creative Commons Zero (CC0).
 https://creativecommons.org/publicdomain/zero/1.0/
 */

import UIKit

import PsiphonTunnel
import Network


enum ProxyType {
    case http
    case socks
}

struct Proxy {
    var host: NWEndpoint.Host
    var type: ProxyType
}

@UIApplicationMain
@objc class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?
    var proxy: Proxy?

    // The instance of PsiphonTunnel we'll use for connecting.
    var psiphonTunnel: PsiphonTunnel?
    
    @objc public class func sharedDelegate() -> AppDelegate {
        var delegate: AppDelegate?
        if (Thread.isMainThread) {
            delegate = UIApplication.shared.delegate as? AppDelegate
        } else {
            DispatchQueue.main.sync {
                delegate = UIApplication.shared.delegate as? AppDelegate
            }
        }
        return delegate!
    }

    internal func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // Override point for customization after application launch.

        self.psiphonTunnel = PsiphonTunnel.newPsiphonTunnel(self)

        // Choose which proxy to use. Callback from PsiphonTunnel will determine the proxy port.
        // If not set, then WKWebView requests are not proxied.
        self.proxy = Proxy(host: "127.0.0.1", type: .http)

        return true
    }

    func applicationWillResignActive(_ application: UIApplication) {
        // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
        // Use this method to pause ongoing tasks, disable timers, and invalidate graphics rendering callbacks. Games should use this method to pause the game.
    }

    func applicationDidEnterBackground(_ application: UIApplication) {
        // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
        // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
    }

    func applicationWillEnterForeground(_ application: UIApplication) {
        // Called as part of the transition from the background to the active state; here you can undo many of the changes made on entering the background.
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.

        DispatchQueue.global(qos: .default).async {
            // Start up the tunnel and begin connecting.
            // This could be started elsewhere or earlier.
            NSLog("Starting tunnel")

            guard let success = self.psiphonTunnel?.start(true), success else {
                NSLog("psiphonTunnel.start returned false")
                return
            }

            // The Psiphon Library exposes reachability functions, which can be used for detecting internet status.
            let reachability = Reachability.forInternetConnection()
            let networkStatus = reachability?.currentReachabilityStatus()
            NSLog("Internet is reachable? \(networkStatus != NotReachable)")
        }
    }

    func applicationWillTerminate(_ application: UIApplication) {
        // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.

        // Clean up the tunnel
        NSLog("Stopping tunnel")
        self.psiphonTunnel?.stop()
    }
}

// MARK: TunneledAppDelegate implementation
// See the protocol definition for details about the methods.
// Note that we're excluding all the optional methods that we aren't using,
// however your needs may be different.
extension AppDelegate: TunneledAppDelegate {
    func getPsiphonConfig() -> Any? {
        // In this example, we're going to retrieve our Psiphon config from a file in the app bundle.
        // Alternatively, it could be a string literal in the code, or whatever makes sense.

        guard let psiphonConfigUrl = Bundle.main.url(forResource: "psiphon-config", withExtension: "json") else {
            NSLog("Error getting Psiphon config resource file URL!")
            return nil
        }

        do {
            return try String.init(contentsOf: psiphonConfigUrl)
        } catch {
            NSLog("Error reading Psiphon config resource file!")
            return nil
        }
    }

    /// Read the Psiphon embedded server entries resource file and return the contents.
    /// * returns: The string of the contents of the file.
    func getEmbeddedServerEntries() -> String? {
        guard let psiphonEmbeddedServerEntriesUrl = Bundle.main.url(forResource: "psiphon-embedded-server-entries", withExtension: "txt") else {
            NSLog("Error getting Psiphon embedded server entries resource file URL!")
            return nil
        }

        do {
            return try String.init(contentsOf: psiphonEmbeddedServerEntriesUrl)
        } catch {
            NSLog("Error reading Psiphon embedded server entries resource file!")
            return nil
        }
    }

    func onDiagnosticMessage(_ message: String, withTimestamp timestamp: String) {
        NSLog("onDiagnosticMessage(%@): %@", timestamp, message)
    }

    func onConnected() {
        NSLog("onConnected")

        DispatchQueue.main.sync {
            let urlString = "https://freegeoip.app/"
            let url = URL.init(string: urlString)!
            let mainView = self.window?.rootViewController as! ViewController
            mainView.loadUrl(url)
        }
    }

    func onListeningSocksProxyPort(_ port: Int) {
        NSLog("onListeningSocksProxyPort: %d", port)

        if case.socks = self.proxy?.type {

            NSLog("Configuring WKWebView to use SOCKS proxy %@:%d", self.proxy!.host.debugDescription, port)

            DispatchQueue.main.async {
                let endpoint = NWEndpoint.hostPort(
                    host: self.proxy!.host,
                    port: NWEndpoint.Port(rawValue:UInt16(port))!)
                let proxyConfig = ProxyConfiguration(socksv5Proxy: endpoint)

                let mainView = self.window?.rootViewController as! ViewController
                mainView.useProxyConfiguration(proxyConfig)
            }
        }
    }

    func onListeningHttpProxyPort(_ port: Int) {
        NSLog("onListeningHttpProxyPort: %d", port)

        if case.http = self.proxy?.type {

            NSLog("Configuring WKWebView to use HTTP proxy %@:%d", self.proxy!.host.debugDescription, port)

            DispatchQueue.main.async {
                let endpoint = NWEndpoint.hostPort(
                    host: self.proxy!.host,
                    port: NWEndpoint.Port(rawValue:UInt16(port))!)
                let proxyConfig = ProxyConfiguration(httpCONNECTProxy: endpoint)

                let mainView = self.window?.rootViewController as! ViewController
                mainView.useProxyConfiguration(proxyConfig)
            }
        }
    }
}
