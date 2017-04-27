//
//  ViewController.swift
//  TunneledWebView
//
/*
Licensed under Creative Commons Zero (CC0).
https://creativecommons.org/publicdomain/zero/1.0/
*/


import UIKit

import PsiphonTunnel

class ViewController: UIViewController {
    
    var webView: UIWebView!
    
    // The instance of PsiphonTunnel we'll use for connecting.
    var psiphonTunnel: PsiphonTunnel?
    
    // These are the ports that we can proxy through.
    var socksProxyPort = -1
    var httpProxyPort = -1
    
    override func loadView() {
        // Make our whole view the webview.
        webView = UIWebView()
        view = webView
        
        self.psiphonTunnel = PsiphonTunnel.newPsiphonTunnel(self)
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Start up the tunnel and begin connecting.
        // This could be started elsewhere or earlier.
        NSLog("Starting tunnel")

        guard let embeddedServerEntries = getEmbeddedServerEntries() else {
            NSLog("getEmbeddedServerEntries failed!")
            return
        }

        guard let success = self.psiphonTunnel?.start(embeddedServerEntries), success else {
            NSLog("psiphonTunnel.start returned false")
            return
        }
        
        // The Psiphon Library exposes reachability functions, which can be used for detecting internet status.
        let reachability = Reachability.forInternetConnection()
        let networkStatus = reachability?.currentReachabilityStatus()
        NSLog("Internet is reachable? \(networkStatus != NotReachable)")
        
        // The Psiphon Library exposes a function to test if the device is jailbroken. 
        let jailbroken = JailbreakCheck.isDeviceJailbroken()
        NSLog("Device is jailbroken? \(jailbroken)")
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    func appendToView(_ text: String) {
        let escapedText = text.replacingOccurrences(of: "\n", with: "\\n")
                              .replacingOccurrences(of: "\r", with: "")
        self.webView.stringByEvaluatingJavaScript(from: String.init(format: "document.body.innerHTML+='<br><pre>%@</pre><br>'", arguments: [escapedText]))
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
    
    /// Request URL using URLSession configured to use the current proxy.
    /// * parameters:
    ///   - url: The URL to request.
    ///   - completion: A callback function that will received the string obtained
    ///     from the request, or nil if there's an error.
    /// * returns: The string obtained from the request, or nil if there's an error.
    func makeRequestViaUrlSessionProxy(_ url: String, completion: @escaping (_ result: String?) -> ()) {
        assert(self.httpProxyPort > 0)
        
        let request = URLRequest(url: URL(string: url)!)
        
        let config = URLSessionConfiguration.ephemeral
        config.requestCachePolicy = URLRequest.CachePolicy.reloadIgnoringLocalCacheData
        config.connectionProxyDictionary = [AnyHashable: Any]()
        
        // Enable and set the SOCKS proxy values.
        config.connectionProxyDictionary?[kCFStreamPropertySOCKSProxy as String] = 1
        config.connectionProxyDictionary?[kCFStreamPropertySOCKSProxyHost as String] = "127.0.0.1"
        config.connectionProxyDictionary?[kCFStreamPropertySOCKSProxyPort as String] = self.socksProxyPort
        
        // Alternatively, the HTTP proxy can be used. Below are the settings for that.
        // The HTTPS key constants are mismatched and Xcode gives deprecation warnings, but they seem to be necessary to proxy HTTPS requests. This is probably a bug on Apple's side; see: https://forums.developer.apple.com/thread/19356#131446
        // config.connectionProxyDictionary?[kCFNetworkProxiesHTTPEnable as String] = 1
        // config.connectionProxyDictionary?[kCFNetworkProxiesHTTPProxy as String] = "127.0.0.1"
        // config.connectionProxyDictionary?[kCFNetworkProxiesHTTPPort as String] = self.httpProxyPort
        // config.connectionProxyDictionary?[kCFStreamPropertyHTTPSProxyHost as String] = "127.0.0.1"
        // config.connectionProxyDictionary?[kCFStreamPropertyHTTPSProxyPort as String] = self.httpProxyPort
        
        let session = URLSession.init(configuration: config, delegate: nil, delegateQueue: OperationQueue.current)
        
        // Create the URLSession task that will make the request via the tunnel proxy.
        let task = session.dataTask(with: request) {
            (data: Data?, response: URLResponse?, error: Error?) in
            if error != nil {
                NSLog("Client-side error in request to \(url): \(error)")
                // Invoke the callback indicating error.
                completion(nil)
                return
            }
            
            if data == nil {
                NSLog("Data from request to \(url) is nil")
                // Invoke the callback indicating error.
                completion(nil)
                return
            }
            
            let httpResponse = response as? HTTPURLResponse
            if httpResponse?.statusCode != 200 {
                NSLog("Server-side error in request to \(url): \(httpResponse)")
                // Invoke the callback indicating error.
                completion(nil)
                return
            }
            
            let encodingName = response?.textEncodingName != nil ? response?.textEncodingName : "utf-8"
            let encoding = CFStringConvertEncodingToNSStringEncoding(CFStringConvertIANACharSetNameToEncoding(encodingName as CFString!))
            
            let stringData = String(data: data!, encoding: String.Encoding(rawValue: UInt(encoding)))
            
            // Make sure the session is cleaned up.
            session.invalidateAndCancel()
            
            // Invoke the callback with the result.
            completion(stringData)
        }
        
        // Start the request task.
        task.resume()
    }

    /// Request URL using Psiphon's "URL proxy" mode. 
    /// For details, see the comment near the top of:
    /// https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/master/psiphon/httpProxy.go
    /// * parameters:
    ///   - url: The URL to request.
    ///   - completion: A callback function that will received the string obtained
    ///     from the request, or nil if there's an error.
    /// * returns: The string obtained from the request, or nil if there's an error.
    func makeRequestViaUrlProxy(_ url: String, completion: @escaping (_ result: String?) -> ()) {
        assert(self.httpProxyPort > 0)
        
        // The target URL must be encoded so as to be valid within a query parameter.
        // See this SO answer for why we're using this CharacterSet (and not using: https://stackoverflow.com/a/24888789
        let queryParamCharsAllowed = CharacterSet.init(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")

        let encodedTargetURL = url.addingPercentEncoding(withAllowedCharacters: queryParamCharsAllowed)
        
        let proxiedURL = "http://127.0.0.1:\(self.httpProxyPort)/tunneled/\(encodedTargetURL!)"
        
        let task = URLSession.shared.dataTask(with: URL(string: proxiedURL)!) {
            (data: Data?, response: URLResponse?, error: Error?) in
            if error != nil {
                NSLog("Client-side error in request to \(url): \(error)")
                // Invoke the callback indicating error.
                completion(nil)
                return
            }
            
            if data == nil {
                NSLog("Data from request to \(url) is nil")
                // Invoke the callback indicating error.
                completion(nil)
                return
            }
            
            let httpResponse = response as? HTTPURLResponse
            if httpResponse?.statusCode != 200 {
                NSLog("Server-side error in request to \(url): \(httpResponse)")
                // Invoke the callback indicating error.
                completion(nil)
                return
            }
            
            let encodingName = response?.textEncodingName != nil ? response?.textEncodingName : "utf-8"
            let encoding = CFStringConvertEncodingToNSStringEncoding(CFStringConvertIANACharSetNameToEncoding(encodingName as CFString!))
            
            let stringData = String(data: data!, encoding: String.Encoding(rawValue: UInt(encoding)))
            
            // Invoke the callback with the result.
            completion(stringData)
        }
        
        // Start the request task.
        task.resume()
    }
}

// MARK: TunneledAppDelegate implementation
// See the protocol definition for details about the methods.
// Note that we're excluding all the optional methods that we aren't using,
// however your needs may be different.
extension ViewController: TunneledAppDelegate {
    func getPsiphonConfig() -> String? {
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
    
    func onDiagnosticMessage(_ message: String) {
        NSLog("onDiagnosticMessage: %@", message)
    }
    
    func onConnected() {
        NSLog("onConnected")
        
        // After we're connected, make tunneled requests and populate the webview.
        
        DispatchQueue.global(qos: .default).async {
            // First we'll make a "what is my IP" request via makeRequestViaUrlSessionProxy().
            let url = "https://freegeoip.net/json/"
            self.makeRequestViaUrlSessionProxy(url) {
                (_ result: String?) in
                
                if result == nil {
                    NSLog("Failed to get \(url)")
                    return
                }

                // Do a little pretty-printing.
                let prettyResult = result?.replacingOccurrences(of: ",", with: ",\n  ")
                                          .replacingOccurrences(of: "{", with: "{\n  ")
                                          .replacingOccurrences(of: "}", with: "\n}")
                
                DispatchQueue.main.sync {
                    // Load the result into the view.
                    self.appendToView("Result from \(url):\n\(prettyResult!)")
                }
                
                // Then we'll make a different "what is my IP" request via makeRequestViaUrlProxy().
                DispatchQueue.global(qos: .default).async {
                    let url = "http://ipinfo.io/json"
                    self.makeRequestViaUrlProxy(url) {
                        (_ result: String?) in
                        
                        if result == nil {
                            NSLog("Failed to get \(url)")
                            return
                        }
                        
                        DispatchQueue.main.sync {
                            // Load the result into the view.
                            self.appendToView("Result from \(url):\n\(result!)")
                        }
                        
                        // We're done with the Psiphon tunnel, so stop it.
                        // In a real app, we would keep this alive for as long as we need it.
                        self.psiphonTunnel?.stop()
                    }
                }
                
            }
        }
    }
    
    func onListeningSocksProxyPort(_ port: Int) {
        NSLog("onListeningSocksProxyPort: %d", port)
        // Record the port being used so that we can proxy through it later.
        DispatchQueue.main.async {
            self.socksProxyPort = port
        }
    }
    
    func onListeningHttpProxyPort(_ port: Int) {
        NSLog("onListeningHttpProxyPort: %d", port)
        // Record the port being used so that we can proxy through it later.
        DispatchQueue.main.async {
            self.httpProxyPort = port
        }
    }
}
