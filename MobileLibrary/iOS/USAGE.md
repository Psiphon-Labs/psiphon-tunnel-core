# Using the Psiphon iOS Library

## Overview

Psiphon Library for iOS enables you to easily embed Psiphon in your iOS app.
You can then tunnel requests through Psiphon, ensuring that your app can't be
blocked by censors.

The Psiphon Library is available as a XCFramework bundle `.xcframework` that can be easily included
in your project using these instructions.

## Requirements

Psiphon Library for iOS requires Xcode 11 or above.
If using CocoaPods, CocoaPods version 1.10 or greater is required.

## Using the Library in your App

**First step:** Review the sample app, located under `SampleApps`.
This code is a canonical guide for integrating the Library.

**Second step:** Review the comments in [`PsiphonTunnel.h`](PsiphonTunnel/PsiphonTunnel/PsiphonTunnel.h). They describe the interface and delegate requirements.

### Setting up your project

1. Get the latest iOS release from the project's [Releases](https://github.com/Psiphon-Labs/psiphon-tunnel-core/releases) page.

2. Add `PsiphonTunnel.xcframework` to project (drag into project tree).

3. In the "General" settings for the target, set "Deployment Target" to 9.3.

4. In the "Build Settings" for the target, under "Build Options", set "Enable Bitcode" to "No".

5. In the "Build Settings" for the target, click the `+` at the top, then "Add User-Defined Setting". Name the new setting `STRIP_BITCODE_FROM_COPIED_FILES` and set it to `NO`.

6. In the "Build Phases" for the target, add a "Copy Files" phase. Set "Destination" to "Frameworks". Add `PsiphonTunnel.xcframework` to the list. Ensure "Code Sign on Copy" is checked.

## Compiling and testing

The following architecture targets are compiled into the Library's framework binary: `arm64`, and `x86_64`. This means that the Library can run on phones or in a simulator (on a 64-bit host system).

When run in a simulator, there may be errors shown in the device log. This does not seem to affect the execution of the app (or Library).

## Proxying a web view

We have provided a reference implementation for proxying `WKWebView` in [TunneledWebView](SampleApps/TunneledWebView). The shortcomings of this implementation are discussed in [SampleApps/TunneledWebView/README.md](SampleApps/TunneledWebView/README.md#-caveats-).

## *\*\* Caveats \*\*\*

### Risk of Online Certificate Status Protocol (OCSP) Leaks

On iOS, remote certificate revocation checks may be performed by the system when server certificates are validated. For example, when making an HTTPS request. When [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) is used to determine the revocation status of a certificate the system will make a plaintext HTTP OCSP request if an OCSP response is not cached or [stapled](https://en.wikipedia.org/wiki/OCSP_stapling).

Unfortunately, these OCSP requests do not respect [connection proxy dictionary settings](https://developer.apple.com/documentation/foundation/nsurlsessionconfiguration/1411499-connectionproxydictionary?language=objc) or [NSURLProtocol](https://developer.apple.com/documentation/foundation/nsurlprotocol) subclasses; instead they are [performed out of process](https://openradar.appspot.com/716337334). The payload in each plaintext OCSP request leaks the identity of the certificate that is being validated.

The risk is that an observer can [map the certificate's serial number back to the certificate](https://github.com/OnionBrowser/OnionBrowser/issues/178#issue-437802301) to find more information about the website or server being accessed.

## Other notes

If you encounter an app crash due to `SIGPIPE`, please let us know. This occurs in the debugger, but it's not clear if it happens in a production app (or is a problem). If you encounter a `SIGPIPE` breakpoint while running under the debugger, follow [these instructions](https://plus.google.com/113241179738681655641/posts/BmMiY8mpsB7) to disable it.
