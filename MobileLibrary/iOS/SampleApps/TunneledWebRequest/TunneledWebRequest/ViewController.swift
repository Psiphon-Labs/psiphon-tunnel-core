//
//  ViewController.swift
//  TunneledWebView
//

import UIKit

import PsiphonTunnel

class ViewController: UIViewController {
    
    var webView: UIWebView!
    
    // The instance of PsiphonTunnel we'll use for connecting.
    var psiphonTunnel: PsiphonTunnel?
    
    // This are the ports that we can proxy through.
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
        // Do any additional setup after loading the view, typically from a nib.
        
        // Start up the tunnel and begin connecting.
        // This could be started elsewhere or earlier.
        NSLog("Starting tunnel")
        
        let embeddedServerEntries = ""
        guard let success = self.psiphonTunnel?.start(embeddedServerEntries), success else {
            NSLog("psiphonTunnel.start returned false")
            return
        }
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
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
            NSLog("Error getting Psiphon config resource file URL!")
            return nil
        }
    }
    
    func onDiagnosticMessage(_ message: String) {
        NSLog("onDiagnosticMessage: %@", message)
    }
    
    func onConnected() {
        NSLog("onConnected")
        
        // After we're connected, make a tunneled request and populate the webview.
        
        DispatchQueue.main.async {
            assert(self.httpProxyPort > 0)
            
            // We'll check out IP to make sure we're tunneled.
            let urlPath: String = "https://freegeoip.net/csv/"
            let url = URL(string: urlPath)!
            let request = URLRequest(url: url)
            
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
                    NSLog("Client-side error in request to \(urlPath): \(error)")
                    return
                }
                
                let httpResponse = response as? HTTPURLResponse
                if httpResponse?.statusCode != 200 {
                    NSLog("Server-side error in request to \(urlPath): \(httpResponse)")
                    return
                }
                
                let encodingName = response?.textEncodingName != nil ? response?.textEncodingName : "utf-8"
                let encoding = CFStringConvertEncodingToNSStringEncoding(CFStringConvertIANACharSetNameToEncoding(encodingName as CFString!))
                
                var stringData = String(data: data!, encoding: String.Encoding(rawValue: UInt(encoding)))
                stringData = stringData?.replacingOccurrences(of: ",", with: "\n")
                
                // Load the IP info result into the web view.
                self.webView.loadHTMLString("<br><pre>\(stringData!)</pre>", baseURL: url)
                
                // Make sure the session is cleaned up.
                session.invalidateAndCancel()
                
                // We're done with the Psiphon tunnel, so stop it.
                // In a real app, we would keep this alive for as long as we need it.
                self.psiphonTunnel?.stop()
            }
            
            // Start the request task.
            task.resume()
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
