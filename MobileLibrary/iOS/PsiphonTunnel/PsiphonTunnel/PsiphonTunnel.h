//
//  PsiphonTunnel.h
//  PsiphonTunnel
//

/*
 * Copyright (c) 2016, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#import <UIKit/UIKit.h>
#import "Reachability.h"
#import "JailbreakCheck.h"


//! Project version number for PsiphonTunnel.
FOUNDATION_EXPORT double PsiphonTunnelVersionNumber;

//! Project version string for PsiphonTunnel.
FOUNDATION_EXPORT const unsigned char PsiphonTunnelVersionString[];

/*!
 @protocol TunneledAppDelegate
 Used to communicate with the application that is using the PsiphonTunnel framework,
 and retrieve config info from it.
 */
@protocol TunneledAppDelegate <NSObject>

//
// Required delegate methods
//
@required

/*!
 Called when tunnel is started to get the library consumer's desired configuration.

 @code
 Required fields:
 - `PropagationChannelId`
 - `SponsorId`
 - Remote server list functionality is not strictly required, but absence greatly undermines circumvention ability.
   - `RemoteServerListURLs`
   - `RemoteServerListSignaturePublicKey`
 - Obfuscated server list functionality is also not strictly required, but aids circumvention ability.
   - `ObfuscatedServerListRootURLs`
   - `RemoteServerListSignaturePublicKey`: This is the same field as above. It is required if either `RemoteServerListURLs` or `ObfuscatedServerListRootURLs` is supplied.

 Optional fields (if you don't need them, don't set them):
 - `DataStoreDirectory`: If not set, the library will use a sane location. Override if the client wants to restrict where operational data is kept. If overridden, the directory must already exist and be writable.
 - `RemoteServerListDownloadFilename`: If not set, the library will use a sane location. Override if the client wants to restrict where operational data is kept.
 - `ObfuscatedServerListDownloadDirectory`: If not set, the library will use a sane location. Override if the client wants to restrict where operational data is kept. If overridden, the directory must already exist and be writable.
 - `UpstreamProxyUrl`
 - `EmitDiagnosticNotices`
 - `EgressRegion`
 - `EstablishTunnelTimeoutSeconds`
 - Should only be set if the Psiphon library is handling upgrade downloading (which it usually is _not_):
   - `UpgradeDownloadURLs`
   - `UpgradeDownloadClientVersionHeader`
   - `UpgradeDownloadFilename`: Will be set to a sane default if not supplied.
 - Only set if disabling timeouts (for very slow network connections):
   - `TunnelConnectTimeoutSeconds`
   - `TunnelPortForwardDialTimeoutSeconds`
   - `TunnelSshKeepAliveProbeTimeoutSeconds`
   - `TunnelSshKeepAlivePeriodicTimeoutSeconds`
   - `FetchRemoteServerListTimeoutSeconds`
   - `PsiphonApiServerTimeoutSeconds`
   - `FetchRoutesTimeoutSeconds`
   - `HttpProxyOriginServerTimeoutSeconds`
 - Fields which should only be set by Psiphon proper:
   - `LocalHttpProxyPort`
   - `LocalSocksProxyPort`
   - `TunnelWholeDevice`: For stats purposes, but must be accurate. Defaults to 0 (false).
 @endcode

 @note All other config fields must not be set.

 See the tunnel-core config code for details about the fields.
 https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/master/psiphon/config.go
 
 @return NSString  JSON string with config that should used to run the Psiphon tunnel, or nil on error.
 
 Swift: @code func getPsiphonConfig() -> String? @endcode
 */
- (NSString * _Nullable)getPsiphonConfig;

//
// Optional delegate methods. Note that some of these are probably necessary for
// for a functioning app to implement, for example `onConnected`.
//
@optional

/*!
 Gets runtime errors info that may be useful for debugging.
 @param message  The diagnostic message string.
 Swift: @code func onDiagnosticMessage(_ message: String) @endcode
 */
- (void)onDiagnosticMessage:(NSString * _Nonnull)message;

/*! 
 Called when the tunnel is in the process of connecting.
 Swift: @code func onConnecting() @endcode
 */
- (void)onConnecting;
/*!
 Called when the tunnel has successfully connected.
 Swift: @code func onConnected() @endcode
 */
- (void)onConnected;

/*!
 Called to indicate that tunnel-core is exiting imminently (usually do to
 a `stop()` call, but could be due to an unexpected error).
 Swift: @code func onExiting() @endcode
 */
- (void)onExiting;

/*!
 Called when tunnel-core determines which server egress regions are available
 for use. This can be used for updating the UI which provides the options to
 the user.
 @param regions  A string array containing the available egress region country codes.
 Swift: @code func onAvailableEgressRegions(_ regions: [Any]) @endcode
 */
- (void)onAvailableEgressRegions:(NSArray * _Nonnull)regions;

/*!
 If the tunnel is started with a fixed SOCKS proxy port, and that port is
 already in use, this will be called.
 @param port  The port number.
 Swift: @code func onSocksProxyPort(inUse port: Int) @endcode
 */
- (void)onSocksProxyPortInUse:(NSInteger)port;
/*!
 If the tunnel is started with a fixed HTTP proxy port, and that port is
 already in use, this will be called.
 @param port  The port number.
 Swift: @code func onHttpProxyPort(inUse port: Int) @endcode
 */
- (void)onHttpProxyPortInUse:(NSInteger)port;

/*!
 Called when tunnel-core determines what port will be used for the local SOCKS proxy.
 @param port  The port number.
 Swift: @code func onListeningSocksProxyPort(_ port: Int) @endcode
 */
- (void)onListeningSocksProxyPort:(NSInteger)port;
/*!
 Called when tunnel-core determines what port will be used for the local HTTP proxy.
 @param port  The port number.
 Swift: @code func onListeningHttpProxyPort(_ port: Int) @endcode
 */
- (void)onListeningHttpProxyPort:(NSInteger)port;

/*!
 Called when a error occurs when trying to utilize a configured upstream proxy.
 @param message  A message giving additional info about the error.
 Swift: @code func onUpstreamProxyError(_ message: String) @endcode
 */
- (void)onUpstreamProxyError:(NSString * _Nonnull)message;

/*!
 Called after the handshake with the Psiphon server, with the client region as determined by the server.
 @param region  The country code of the client, as determined by the server.
 Swift: @code func onClientRegion(_ region: String) @endcode
 */
- (void)onClientRegion:(NSString * _Nonnull)region;

/*!
 Called to report that split tunnel is on for the given region.
 @param region  The region split tunnel is on for.
 Swift: @code func onSplitTunnelRegion(_ region: String) @endcode
 */
- (void)onSplitTunnelRegion:(NSString * _Nonnull)region;

/*!
 Called to indicate that an address has been classified as being within the
 split tunnel region and therefore is being access directly rather than tunneled.
 Note: `address` should remain private; this notice should be used for alerting
 users, not for diagnotics logs.
 @param address  The IP or hostname that is not being tunneled.
 Swift: @code func onUntunneledAddress(_ address: String) @endcode
 */
- (void)onUntunneledAddress:(NSString * _Nonnull)address;

/*!
 Called to report how many bytes have been transferred since the last time
 this function was called.
 @param sent  The number of bytes sent.
 @param received  The number of bytes received.
 Swift: @code func onBytesTransferred(_ sent: Int64, _ received: Int64) @endcode
 */
- (void)onBytesTransferred:(int64_t)sent :(int64_t)received;

/*!
 Called when tunnel-core discovers a home page associated with this client.
 If there are no home pages, it will not be called. May be called more than
 once, for multiple home pages.
 Note: This is probably only applicable to Psiphon Inc.'s apps.
 @param url  The URL of the home page.
 Swift: @code func onHomepage(_ url: String) @endcode
 */
- (void)onHomepage:(NSString * _Nonnull)url;

/*!
 Called if the current version of the client is the latest (i.e., there is no upgrade available).
 Note: This is probably only applicable to Psiphon Inc.'s apps.
 Swift: @code func onClientIsLatestVersion() @endcode
 */
- (void)onClientIsLatestVersion;

/*!
 Called when a client upgrade has been downloaded.
 @param filename  The name of the file containing the upgrade.
 Note: This is probably only applicable to Psiphon Inc.'s apps.
 Swift: @code func onClientUpgradeDownloaded(_ filename: String) @endcode
 */
- (void)onClientUpgradeDownloaded:(NSString * _Nonnull)filename;

@end

/*!
 The interface for managing the Psiphon tunnel -- set up, tear down, receive info about.
 */
@interface PsiphonTunnel : NSObject

/*!
 Returns an instance of PsiphonTunnel. This is either a new instance or the pre-existing singleton. If an instance already exists, it will be stopped when this function is called.
 @param tunneledAppDelegate  The delegate implementation to use for callbacks.
 @return  The PsiphonTunnel instance.
 */
+ (PsiphonTunnel * _Nonnull)newPsiphonTunnel:(id<TunneledAppDelegate> _Nonnull)tunneledAppDelegate;

/*!
 Start connecting the PsiphonTunnel. Returns before connection is complete -- delegate callbacks (such as `onConnected`) are used to indicate progress and state.
 @param embeddedServerEntries  Pre-existing server entries to use when attempting to connect to a server. May be null if there are no embedded server entries.
 @return TRUE if the connection start was successful, FALSE otherwise.
 */
- (BOOL)start:(NSString * _Nullable)embeddedServerEntries;

/*!
 Stop the tunnel (regardless of its current connection state). Returns before full stop is complete -- `TunneledAppDelegate::onExiting` is called when complete.
 */
- (void)stop;

/*!
 Upload a feedback package to Psiphon Inc. The app collects feedback and diagnostics information in a particular format, then calls this function to upload it for later investigation.
 @note The key, server, path, and headers must be provided by Psiphon Inc.
 @param feedbackJson  The feedback and diagnostics data to upload.
 @param b64EncodedPublicKey  The key that will be used to encrypt the payload before uploading.
 @param uploadServer  The server and path to which the data will be uploaded.
 @param uploadServerHeaders  The request headers that will be used when uploading.
 */
- (void)sendFeedback:(NSString * _Nonnull)feedbackJson
           publicKey:(NSString * _Nonnull)b64EncodedPublicKey
        uploadServer:(NSString * _Nonnull)uploadServer
 uploadServerHeaders:(NSString * _Nonnull)uploadServerHeaders;

@end
