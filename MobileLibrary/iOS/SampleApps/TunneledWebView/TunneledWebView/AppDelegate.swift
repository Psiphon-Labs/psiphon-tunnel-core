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


@UIApplicationMain
@objc class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?
    @objc public var socksProxyPort: Int = 0
    @objc public var httpProxyPort: Int = 0

    // The instance of PsiphonTunnel we'll use for connecting.
    var psiphonTunnel: PsiphonTunnel?

    // OCSP cache for making OCSP requests in certificate revocation checking
    var ocspCache: OCSPCache = OCSPCache.init(logger: {print("[OCSPCache]:", $0)})

    // Delegate for handling certificate validation.
    @objc public lazy var authURLSessionDelegate: OCSPAuthURLSessionDelegate =
        OCSPAuthURLSessionDelegate.init(logger: {print("[AuthURLSessionTaskDelegate]:", $0)},
                                        ocspCache: self.ocspCache,
                                        // Unlike TunneledWebRequest we do not need to manually
                                        // update the OCSP request to be proxied through the local
                                        // HTTP proxy. Since JAHPAuthenticatingHTTPProtocol
                                        // subclasses and registers itself with NSURLProtocol, all
                                        // URL requests made manually (using the foundation
                                        // framework) will be proxied automatically.
                                        //
                                        // Since the OCSPCache library makes requests using
                                        // NSURLSessionDataTask, the OCSP requests will be proxied
                                        // automatically.
                                        modifyOCSPURL:nil,
                                        session:nil,
                                        timeout:10)
    
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

        // Set the class delegate and register NSURL subclass
        // JAHPAuthenticatingHTTPProtocol with NSURLProtocol.
        // See comments for `setDelegate` and `start` in
        // JAHPAuthenticatingHTTPProtocol.h
        /*******************************************************/
        /*****                                             *****/
        /*****               !!! WARNING !!!               *****/
        /*****                                             *****/
        /*******************************************************/
        /*****                                             *****/
        /*****  This methood of proxying UIWebView is not  *****/
        /*****  officially supported and requires extra    *****/
        /*****  steps to proxy audio / video content.      *****/
        /*****  Otherwise audio / video fetching may be    *****/
        /*****  untunneled!                                *****/
        /*****                                             *****/
        /*****  It is strongly advised that you read the   *****/
        /*****  "Caveats" section of README.md before      *****/
        /*****  using PsiphonTunnel to proxy UIWebView     *****/
        /*****  traffic.                                   *****/
        /*****                                             *****/
        /*******************************************************/
        JAHPAuthenticatingHTTPProtocol.setDelegate(self)
        JAHPAuthenticatingHTTPProtocol.start()

        self.psiphonTunnel = PsiphonTunnel.newPsiphonTunnel(self)

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

extension AppDelegate: JAHPAuthenticatingHTTPProtocolDelegate {
    func authenticatingHTTPProtocol(_ authenticatingHTTPProtocol: JAHPAuthenticatingHTTPProtocol?, logMessage message: String) {
        NSLog("[JAHPAuthenticatingHTTPProtocol] %@", message)
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
        DispatchQueue.main.async {
            JAHPAuthenticatingHTTPProtocol.resetSharedDemux()
            self.socksProxyPort = port
        }
    }

    func onListeningHttpProxyPort(_ port: Int) {
        DispatchQueue.main.async {
            JAHPAuthenticatingHTTPProtocol.resetSharedDemux()
            self.httpProxyPort = port
        }
    }
}
