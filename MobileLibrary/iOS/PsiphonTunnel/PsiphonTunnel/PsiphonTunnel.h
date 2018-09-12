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
 The set of possible connection states the tunnel can be in.
 Swift:
 @code
 public enum PsiphonConnectionState : Int {
     case disconnected
     case connecting
     case connected
     case waitingForNetwork
 }
 @endcode
 */
typedef NS_ENUM(NSInteger, PsiphonConnectionState)
{
    PsiphonConnectionStateDisconnected = 0,
    PsiphonConnectionStateConnecting,
    PsiphonConnectionStateConnected,
    PsiphonConnectionStateWaitingForNetwork
};


/*!
 @protocol TunneledAppDelegate
 Used to communicate with the application that is using the PsiphonTunnel framework,
 and retrieve config info from it.

 All delegate methods will be called on a single serial dispatch queue. They will be made asynchronously unless otherwise noted (specifically when calling getPsiphonConfig and getEmbeddedServerEntries).
 */
@protocol TunneledAppDelegate <NSObject>

//
// Required delegate methods
//
@required

/*!
 Called when tunnel is starting to get the library consumer's desired configuration.

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
   - `TunnelWholeDevice`
   - `LocalHttpProxyPort`
   - `LocalSocksProxyPort`
 @endcode

 @note All other config fields must not be set.

 See the tunnel-core config code for details about the fields.
 https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/master/psiphon/config.go

 @return Either JSON NSString with config that should be used to run the Psiphon tunnel,
         or return already parsed JSON as NSDictionary,
         or nil on error.

 Swift: @code func getPsiphonConfig() -> Any? @endcode
 */
- (id _Nullable)getPsiphonConfig;

/*!
 Called when the tunnel is starting to get the initial server entries (typically embedded in the app) that will be used to bootstrap the Psiphon tunnel connection. This value is in a particular format and will be supplied by Psiphon Inc.
 If getEmbeddedServerEntriesPath is also implemented, it will take precedence over this method, unless getEmbeddedServerEntriesPath returns NULL or an empty string.
 @return  Pre-existing server entries to use when attempting to connect to a server. Must return an empty string if there are no embedded server entries. Must return NULL if there is an error and the tunnel starting should abort.
 */
- (NSString * _Nullable)getEmbeddedServerEntries;

//
// Optional delegate methods. Note that some of these are probably necessary for
// for a functioning app to implement, for example `onConnected`.
//
@optional

/*!
  Called when the tunnel is starting to get the initial server entries (typically embedded in the app) that will be used to bootstrap the Psiphon tunnel connection. This value is in a particular format and will be supplied by Psiphon Inc.
  If this method is implemented, it takes precedence over getEmbeddedServerEntries, and getEmbeddedServerEntries will not be called unless this method returns NULL or an empty string.
  @return Optional path where embedded server entries file is located. This file should be readable by the library.
 */
- (NSString * _Nullable)getEmbeddedServerEntriesPath;

/*!
  Called when the tunnel is starting. If this method is implemented, it should return the path where a homepage
  notices file is to be written. This path should be writable by the library.
 */
- (NSString * _Nullable)getHomepageNoticesPath;

/*!
  Called when the tunnel is starting. If this method is implemented, it should return the path where a rotating
  notice file set is to be written. path file should be writable by the library.
 */
- (NSString * _Nullable)getRotatingNoticesPath;

/*!
 Gets runtime errors info that may be useful for debugging.
 @param message  The diagnostic message string.
 @param timestamp RFC3339 encoded timestamp.
 Swift: @code func onDiagnosticMessage(_ message: String) @endcode
 */
- (void)onDiagnosticMessage:(NSString * _Nonnull)message withTimestamp:(NSString * _Nonnull)timestamp;

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
 Called when the tunnel notices that the device has no network connectivity and
 begins waiting to regain it. When connecitvity is regained, `onConnecting`
 will be called.
 Swift: @code func onStartedWaitingForNetworkConnectivity @endcode
 */
- (void)onStartedWaitingForNetworkConnectivity;

/*!
 Called when the tunnel's connection state changes.
 Note that this will be called _in addition to, but before_ `onConnecting`, etc.
 Also note that this will not be called for the initial disconnected state
 (since it didn't change from anything).
 @param oldState  The previous connection state.
 @param newState  The new connection state.
 Swift: @code func onConnectionStateChanged(from oldState: PsiphonConnectionState, to newState: PsiphonConnectionState) @endcode
 */
- (void)onConnectionStateChangedFrom:(PsiphonConnectionState)oldState to:(PsiphonConnectionState)newState;

/*!
 Called to indicate that tunnel-core is exiting imminently (usually due to
 a `stop()` call, but could be due to an unexpected error).
 onExiting may be called before or after `stop()` returns.
 Swift: @code func onExiting() @endcode
 */
- (void)onExiting;

/*!
Called when the device's Internet connection state has changed.
This may mean that it had connectivity and now doesn't, or went from Wi-Fi to
WWAN or vice versa or VPN state changed
Swift: @code func onInternetReachabilityChanged(_ currentReachability: Reachability) @endcode
*/
- (void)onInternetReachabilityChanged:(Reachability * _Nonnull)currentReachability;

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
 By default onBytesTransferred is disabled. Enable it by setting
 EmitBytesTransferred to true in the Psiphon config.
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
 Called when tunnel-core receives server timetamp in the handshake
 @param timestamp  The server timestamp in RFC3339 format.
 Swift: @code func onServerTimestamp(_ timestamp: String) @endcode
 */
- (void)onServerTimestamp:(NSString * _Nonnull)timestamp;

/*!
 Called when tunnel-core receives an array of active authorization IDs in the handshake
 @param authorizations  A string array containing active authorization IDs.
 Swift: @code func onActiveAuthorizationIDs(_ authorizations: [Any]) @endcode
 */
- (void)onActiveAuthorizationIDs:(NSArray * _Nonnull)authorizations;

@end

/*!
 The interface for managing the Psiphon tunnel -- set up, tear down, receive info about.
 */
@interface PsiphonTunnel : NSObject

/*!
 Returns an instance of PsiphonTunnel. This is either a new instance or the pre-existing singleton. If an instance already exists, it will be stopped when this function is called.
 @param tunneledAppDelegate  The delegate implementation to use for callbacks.
 @return  The PsiphonTunnel instance.
 Swift: @code class func newPsiphonTunnel(_ tunneledAppDelegate: TunneledAppDelegate) -> Self @endcode
 */
+ (PsiphonTunnel * _Nonnull)newPsiphonTunnel:(id<TunneledAppDelegate> _Nonnull)tunneledAppDelegate;

/*!
 Start connecting the PsiphonTunnel. Returns before connection is complete -- delegate callbacks (such as `onConnected` and `onConnectionStateChanged`) are used to indicate progress and state.
 @param ifNeeded  If TRUE, the tunnel will only be started if it's not already connected and healthy. If FALSE, the tunnel will be forced to stop and reconnect.
 @return TRUE if the connection start was successful, FALSE otherwise.
 Swift: @code func start(_ ifNeeded: Bool) -> Bool @endcode
 */
- (BOOL)start:(BOOL)ifNeeded;


/*!
 Reconnect a previously started PsiphonTunnel with the specified config changes.
 reconnectWithConfig has no effect if there is no running PsiphonTunnel.
 */
- (void)reconnectWithConfig:(NSString * _Nullable) newSponsorID :(NSArray<NSString *> *_Nullable)newAuthorizations;

/*!
 Force stops the tunnel and reconnects with the current session ID.
 Retuns with FALSE immediately if no session ID has already been generated.

 @note On the first connection `start:` method should always be used to generate a
 session ID.

 @return TRUE if the connection start was successful, FALSE otherwise.
 Swift: @code func startWithCurrentSessionID() @endcode
 */
- (BOOL)stopAndReconnectWithCurrentSessionID;

/*!
 Stop the tunnel (regardless of its current connection state).
 Swift: @code func stop() @endcode
 */
- (void)stop;

/*!
 Indicate if the device is sleeping. This logs a diagnostic message and forces hasNetworkConnectivity to false when sleeping.
 Swift: @code func setSleeping(_ isSleeping: Bool) @endcode
 */
- (void)setSleeping:(BOOL)isSleeping;

/*!
 Returns the current tunnel connection state.
 @return  The current connection state.
 Swift: @code func getConnectionState() -> PsiphonConnectionState @endcode
 */
- (PsiphonConnectionState)getConnectionState;

/*!
 Provides the port number of the local SOCKS proxy. Only valid when currently connected (will return 0 otherwise).
 @return  The current local SOCKS proxy port number.
 Swift: @code func getLocalSocksProxyPort() -> Int @endcode
 */
- (NSInteger)getLocalSocksProxyPort;

/*!
 Provides the port number of the local HTTP proxy. Only valid when currently connected (will return 0 otherwise).
 @return  The current local HTTP proxy port number.
 Swift: @code func getLocalHttpProxyPort() -> Int @endcode
 */
- (NSInteger)getLocalHttpProxyPort;

/*!
 Only valid in whole device mode. Provides the MTU the packet tunnel requires the device to use.
 @return  The MTU size.
 Swift: @code func getPacketTunnelMTU() -> Int @endcode
 */
- (long)getPacketTunnelMTU;

/*!
 Only valid in whole device mode. Provides the DNS resolver IP address that is provided by the packet tunnel to the device.
  @return  The IP address of the DNS resolver as a string.
  Swift: @code func getPacketTunnelDNSResolverIPv4Address() -> String @endcode
 */
- (NSString * _Nonnull)getPacketTunnelDNSResolverIPv4Address;

/*!
 Only valid in whole device mode. Provides the DNS resolver IP address that is provided by the packet tunnel to the device.
 @return  The IP address of the DNS resolver as a string.
  Swift: @code func getPacketTunnelDNSResolverIPv6Address() -> String @endcode
 */
- (NSString * _Nonnull)getPacketTunnelDNSResolverIPv6Address;

/*!
 Upload a feedback package to Psiphon Inc. The app collects feedback and diagnostics information in a particular format, then calls this function to upload it for later investigation.
 @note The key, server, path, and headers must be provided by Psiphon Inc.
 @param feedbackJson  The feedback and diagnostics data to upload.
 @param b64EncodedPublicKey  The key that will be used to encrypt the payload before uploading.
 @param uploadServer  The server and path to which the data will be uploaded.
 @param uploadServerHeaders  The request headers that will be used when uploading.
 Swift: @code func sendFeedback(_ feedbackJson: String, publicKey b64EncodedPublicKey: String, uploadServer: String, uploadServerHeaders: String) @endcode
 */
- (void)sendFeedback:(NSString * _Nonnull)feedbackJson
           publicKey:(NSString * _Nonnull)b64EncodedPublicKey
        uploadServer:(NSString * _Nonnull)uploadServer
 uploadServerHeaders:(NSString * _Nonnull)uploadServerHeaders;

/*!
 Provides the tunnel-core build info json as a string. See the tunnel-core build info code for details https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/master/psiphon/common/buildinfo.go.
 @return  The build info json as a string.
 Swift: @code func getBuildInfo() -> String @endcode
 */
+ (NSString * _Nonnull)getBuildInfo;

 @end
