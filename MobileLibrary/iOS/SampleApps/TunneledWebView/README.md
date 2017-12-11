# iOS Library Sample App: TunneledWebView

## Tunneling UIWebView
*Note: NSURLProtocol is only partially supported by UIWebView (https://bugs.webkit.org/show_bug.cgi?id=138169) and in iOS 9 (and perhaps other versions of iOS) audio and video are fetched out of process in mediaserverd and therefore not intercepted by NSURLProtocol.*

*Note: this approach does not work with WKWebView (see [http://www.openradar.me/17190141](http://www.openradar.me/17190141)).*

This app tunnels UIWebView traffic by proxying requests through the local Psiphon proxies created by [PsiphonTunnel](https://github.com/Psiphon-Labs/psiphon-tunnel-core/tree/master/MobileLibrary/iOS/PsiphonTunnel).
The listening Psiphon proxy ports can be obtained via TunneledAppDelegate delegate callbacks (see `onListeningSocksProxyPort` and `onListeningHttpProxyPort` in `AppDelegate.swift`).

This is accomplished by registering `NSURLProtocol` subclass `JAHPAuthenticatingHTTPProtocol` with `NSURLProtocol`.
`JAHPAuthenticatingHTTPProtocol` is then configured to use the local Psiphon proxies.
This is done by setting the [connectionProxyDictionary](https://developer.apple.com/documentation/foundation/nsurlsessionconfiguration/1411499-connectionproxydictionary?language=objc) of [NSURLSessionConfiguration](https://developer.apple.com/documentation/foundation/nsurlsessionconfiguration).
See `+ (JAHPQNSURLSessionDemux *)sharedDemux` in `JAHPAuthenticatingHTTPProtocol.m`.

We use a slightly modified version of JiveAuthenticatingProtocol (https://github.com/jivesoftware/JiveAuthenticatingHTTPProtocol), which in turn is largely based on [Apple's CustomHTTPProtocol example](https://developer.apple.com/library/content/samplecode/CustomHTTPProtocol/Introduction/Intro.html). 

## Configuring, Building, Running

The sample app requires some extra files and configuration before building.

### Get the framework.

1. Get the latest iOS release from the project's [Releases](https://github.com/Psiphon-Labs/psiphon-tunnel-core/releases) page.
2. Extract the archive. 
2. Copy `PsiphonTunnel.framework` into the `TunneledWebView` directory.

### Get the configuration.

1. Contact Psiphon Inc. to obtain configuration values to use in your app. 
   (This is requried to use the Psiphon network.)
2. Make a copy of `TunneledWebView/psiphon-config.json.stub`, 
   removing the `.stub` extension.
3. Edit `psiphon-config.json`. Remove the comments and fill in the values with 
   those received from Psiphon Inc. The `"ClientVersion"` value is up to you.

### Ready!

TunneledWebView should now compile and run.

### Loading different URLs

Just update `urlString = "https://freegeoip.net"` in `onConnected` to load a different URL into `UIWebView` with TunneledWebView.

## License

See the [LICENSE](../LICENSE) file.
