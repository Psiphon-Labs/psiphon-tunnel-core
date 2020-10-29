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
 */
typedef NS_ENUM(NSInteger, PsiphonConnectionState)
{
    PsiphonConnectionStateDisconnected = 0,
    PsiphonConnectionStateConnecting,
    PsiphonConnectionStateConnected,
    PsiphonConnectionStateWaitingForNetwork
};

/*!
 @protocol PsiphonTunnelLoggerDelegate
 Used to communicate diagnostic logs to the application that is using the PsiphonTunnel framework.
 */
@protocol PsiphonTunnelLoggerDelegate <NSObject>

@optional

/*!
 Gets runtime errors info that may be useful for debugging.
 @param message  The diagnostic message string.
 @param timestamp RFC3339 encoded timestamp.
 */
- (void)onDiagnosticMessage:(NSString * _Nonnull)message withTimestamp:(NSString * _Nonnull)timestamp;

@end

/*!
 @protocol TunneledAppDelegate
 Used to communicate with the application that is using the PsiphonTunnel framework,
 and retrieve config info from it.

 All delegate methods will be called on a single serial dispatch queue. They will be made asynchronously unless otherwise noted (specifically when calling getPsiphonConfig and getEmbeddedServerEntries).
 */
@protocol TunneledAppDelegate <NSObject, PsiphonTunnelLoggerDelegate>

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
 */
- (id _Nullable)getPsiphonConfig;

//
// Optional delegate methods. Note that some of these are probably necessary for
// for a functioning app to implement, for example `onConnected`.
//
@optional

/*!
 Called when the tunnel is starting to get the initial server entries (typically embedded in the app) that will be used to bootstrap the Psiphon tunnel connection. This value is in a particular format and will be supplied by Psiphon Inc.
 If getEmbeddedServerEntriesPath is also implemented, it will take precedence over this method, unless getEmbeddedServerEntriesPath returns NULL or an empty string.
 @return  Pre-existing server entries to use when attempting to connect to a server. Must return an empty string if there are no embedded server entries. Must return NULL if there is an error and the tunnel starting should abort.
 */
- (NSString * _Nullable)getEmbeddedServerEntries;

/*!
  Called when the tunnel is starting to get the initial server entries (typically embedded in the app) that will be used to bootstrap the Psiphon tunnel connection. This value is in a particular format and will be supplied by Psiphon Inc.
  If this method is implemented, it takes precedence over getEmbeddedServerEntries, and getEmbeddedServerEntries will not be called unless this method returns NULL or an empty string.
  @return Optional path where embedded server entries file is located. This file should be readable by the library.
 */
- (NSString * _Nullable)getEmbeddedServerEntriesPath;

/*!
 Called when the tunnel is in the process of connecting.
 */
- (void)onConnecting;
/*!
 Called when the tunnel has successfully connected.
 */
- (void)onConnected;

/*!
 Called when the tunnel notices that the device has no network connectivity and
 begins waiting to regain it. When connecitvity is regained, `onConnecting`
 will be called.
 */
- (void)onStartedWaitingForNetworkConnectivity;

/*!
 Called when the tunnel's connection state changes.
 Note that this will be called _in addition to, but before_ `onConnecting`, etc.
 Also note that this will not be called for the initial disconnected state
 (since it didn't change from anything).
 @param oldState  The previous connection state.
 @param newState  The new connection state.
 */
- (void)onConnectionStateChangedFrom:(PsiphonConnectionState)oldState to:(PsiphonConnectionState)newState;

/*!
 Called to indicate that tunnel-core is exiting imminently (usually due to
 a `stop()` call, but could be due to an unexpected error).
 onExiting may be called before or after `stop()` returns.
 */
- (void)onExiting;

/*!
Called when the device's Internet connection state has changed.
This may mean that it had connectivity and now doesn't, or went from Wi-Fi to
WWAN or vice versa or VPN state changed
*/
- (void)onInternetReachabilityChanged:(Reachability * _Nonnull)currentReachability;

/*!
 Called when tunnel-core determines which server egress regions are available
 for use. This can be used for updating the UI which provides the options to
 the user.
 @param regions  A string array containing the available egress region country codes.
 */
- (void)onAvailableEgressRegions:(NSArray * _Nonnull)regions;

/*!
 If the tunnel is started with a fixed SOCKS proxy port, and that port is
 already in use, this will be called.
 @param port  The port number.
 */
- (void)onSocksProxyPortInUse:(NSInteger)port;
/*!
 If the tunnel is started with a fixed HTTP proxy port, and that port is
 already in use, this will be called.
 @param port  The port number.
 */
- (void)onHttpProxyPortInUse:(NSInteger)port;

/*!
 Called when tunnel-core determines what port will be used for the local SOCKS proxy.
 @param port  The port number.
 */
- (void)onListeningSocksProxyPort:(NSInteger)port;
/*!
 Called when tunnel-core determines what port will be used for the local HTTP proxy.
 @param port  The port number.
 */
- (void)onListeningHttpProxyPort:(NSInteger)port;

/*!
 Called when a error occurs when trying to utilize a configured upstream proxy.
 @param message  A message giving additional info about the error.
 */
- (void)onUpstreamProxyError:(NSString * _Nonnull)message;

/*!
 Called after the handshake with the Psiphon server, with the client region as determined by the server.
 @param region  The country code of the client, as determined by the server.
 */
- (void)onClientRegion:(NSString * _Nonnull)region;

/*!
 Called to report that split tunnel is on for the given region.
 @param region  The region split tunnel is on for.
 */
- (void)onSplitTunnelRegion:(NSString * _Nonnull)region;

/*!
 Called to indicate that an address has been classified as being within the
 split tunnel region and therefore is being access directly rather than tunneled.
 Note: `address` should remain private; this notice should be used for alerting
 users, not for diagnotics logs.
 @param address  The IP or hostname that is not being tunneled.
 */
- (void)onUntunneledAddress:(NSString * _Nonnull)address;

/*!
 Called to report how many bytes have been transferred since the last time
 this function was called.
 By default onBytesTransferred is disabled. Enable it by setting
 EmitBytesTransferred to true in the Psiphon config.
 @param sent  The number of bytes sent.
 @param received  The number of bytes received.
 */
- (void)onBytesTransferred:(int64_t)sent :(int64_t)received;

/*!
 Called when tunnel-core discovers a home page associated with this client.
 If there are no home pages, it will not be called. May be called more than
 once, for multiple home pages.
 Note: This is probably only applicable to Psiphon Inc.'s apps.
 @param url  The URL of the home page.
 */
- (void)onHomepage:(NSString * _Nonnull)url;

/*!
 Called when tunnel-core receives server timetamp in the handshake
 @param timestamp  The server timestamp in RFC3339 format.
 */
- (void)onServerTimestamp:(NSString * _Nonnull)timestamp;

/*!
 Called when tunnel-core receives an array of active authorization IDs in the handshake
 @param authorizations  A string array containing active authorization IDs.
 */
- (void)onActiveAuthorizationIDs:(NSArray * _Nonnull)authorizations;

/*!
 Called when tunnel-core receives traffic rate limit information in the handshake
 @param upstreamBytesPerSecond  upstream rate limit; 0 for no limit
 @param downstreamBytesPerSecond  downstream rate limit; 0 for no limit
 */
- (void)onTrafficRateLimits:(int64_t)upstreamBytesPerSecond :(int64_t)downstreamBytesPerSecond;

/*!
 Called when tunnel-core receives an alert from the server.
 @param reason The reason for the alert.
 @param subject Additional context or classification of the reason; blank for none.
 */
- (void)onServerAlert:(NSString * _Nonnull)reason :(NSString * _Nonnull)subject;

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
Returns the default data root directory that is used by PsiphonTunnel if DataRootDirectory is not specified in the config returned by
getPsiphonConfig.
@param err Any error encountered while obtaining the default data root directory. If set, the return value should be ignored.
@return  The default data root directory used by PsiphonTunnel.
*/
+ (NSURL * _Nullable)defaultDataRootDirectoryWithError:(NSError * _Nullable * _Nonnull)err;

/*!
Returns the path where the homepage notices file will be created.
@note    This file will only be created if UseNoticeFiles is set in the config returned by `getPsiphonConfig`.
@param dataRootDirectory the configured data root directory. If DataRootDirectory is not specified in the config returned by
getPsiphonConfig, then use `defaultDataRootDirectory`.
@return  The file path at which the homepage file will be created.
*/
+ (NSURL * _Nullable)homepageFilePath:(NSURL * _Nonnull)dataRootDirectory;

/*!
Returns the path where the notices file will be created. When the file is rotated it will be moved to `oldNoticesFilePath`.
@note    This file will only be created if UseNoticeFiles is set in the config returned by `getPsiphonConfig`.
@param dataRootDirectory the configured data root directory. If DataRootDirectory is not specified in the config returned by
`getPsiphonConfig`, then use `defaultDataRootDirectory`.
@return  The file path at which the notices file will be created.
*/
+ (NSURL * _Nullable)noticesFilePath:(NSURL * _Nonnull)dataRootDirectory;

/*!
Returns the path where the rotated notices file will be created.
@note    This file will only be created if UseNoticeFiles is set in the config returned by `getPsiphonConfig`.
@param dataRootDirectory the configured data root directory. If DataRootDirectory is not specified in the config returned by
`getPsiphonConfig`, then use `defaultDataRootDirectory`.
@return  The file path at which the rotated notices file can be found once rotated.
*/
+ (NSURL * _Nullable)olderNoticesFilePath:(NSURL * _Nonnull)dataRootDirectory;

/*!
 Start connecting the PsiphonTunnel. Returns before connection is complete -- delegate callbacks (such as `onConnected` and `onConnectionStateChanged`) are used to indicate progress and state.
 @param ifNeeded  If TRUE, the tunnel will only be started if it's not already connected and healthy. If FALSE, the tunnel will be forced to stop and reconnect.
 @return TRUE if the connection start was successful, FALSE otherwise.
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
 */
- (BOOL)stopAndReconnectWithCurrentSessionID;

/*!
 Stop the tunnel (regardless of its current connection state).
 */
- (void)stop;

/*!
 Returns the current tunnel connection state.
 @return  The current connection state.
 */
- (PsiphonConnectionState)getConnectionState;

/*!
 Returns the current network reachability status, if Psiphon tunnel is not in a
 disconnected state.
 @return The current reachability status.
 */
- (BOOL)getNetworkReachabilityStatus:(NetworkStatus * _Nonnull)status;

/*!
 Provides the port number of the local SOCKS proxy. Only valid when currently connected (will return 0 otherwise).
 @return  The current local SOCKS proxy port number.
 */
- (NSInteger)getLocalSocksProxyPort;

/*!
 Provides the port number of the local HTTP proxy. Only valid when currently connected (will return 0 otherwise).
 @return  The current local HTTP proxy port number.
 */
- (NSInteger)getLocalHttpProxyPort;

/*!
 Only valid in whole device mode. Provides the MTU the packet tunnel requires the device to use.
 @return  The MTU size.
 */
- (long)getPacketTunnelMTU;

/*!
 Only valid in whole device mode. Provides the DNS resolver IP address that is provided by the packet tunnel to the device.
  @return  The IP address of the DNS resolver as a string.
 */
- (NSString * _Nonnull)getPacketTunnelDNSResolverIPv4Address;

/*!
 Only valid in whole device mode. Provides the DNS resolver IP address that is provided by the packet tunnel to the device.
 @return  The IP address of the DNS resolver as a string.
 */
- (NSString * _Nonnull)getPacketTunnelDNSResolverIPv6Address;

/*!
 Provides the tunnel-core build info json as a string. See the tunnel-core build info code for details https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/master/psiphon/common/buildinfo.go.
 @return  The build info json as a string.
 */
+ (NSString * _Nonnull)getBuildInfo;

#pragma mark - Profiling utitlities

/*!
 Writes Go runtime profile information to a set of files in the specifiec output directory.
 @param cpuSampleDurationSeconds determines how to long to wait and sample profiles that require active sampling. When set to 0, these profiles are skipped.
 @param blockSampleDurationSeconds determines how to long to wait and sample profiles that require active sampling. When set to 0, these profiles are skipped.
 */
- (void)writeRuntimeProfilesTo:(NSString * _Nonnull)outputDirectory withCPUSampleDurationSeconds:(int)cpuSampleDurationSeconds withBlockSampleDurationSeconds:(int)blockSampleDurationSeconds;

 @end

/*!
 @protocol PsiphonTunnelFeedbackDelegate
 Used to communicate the outcome of feedback upload operations to the application using the PsiphonTunnel framework.
 */
@protocol PsiphonTunnelFeedbackDelegate <NSObject>

/// Called once the feedback upload has completed.
/// @param err If non-nil, then the upload failed.
- (void)sendFeedbackCompleted:(NSError * _Nullable)err;

@end

/*!
 The interface for managing the Psiphon tunnel feedback upload operations.
 @warning Should not be used in the same process as PsiphonTunnel.
 @warning Only a single instance of PsiphonTunnelFeedback should be used at a time. Using multiple instances in parallel, or
 concurrently, will result in undefined behavior.
 */
@interface PsiphonTunnelFeedback : NSObject

/*!
 Upload a feedback package to Psiphon Inc. The app collects feedback and diagnostics information in a particular format and then calls this
 function to upload it for later investigation. This call is asynchronous and returns before the upload completes. The operation has
 completed when `sendFeedbackCompleted:` is called on the provided `PsiphonTunnelFeedbackDelegate`.
 @param feedbackJson The feedback data to upload.
 @param feedbackConfigJson The feedback compatible config. Must be an NSDictionary or NSString. Config must be provided by
 Psiphon Inc.
 @param uploadPath The path at which to upload the diagnostic data. Must be provided by Psiphon Inc.
 @param loggerDelegate Optional delegate which will be called to log informational notices, including warnings. Stored as a weak
 reference; the caller is responsible for holding a strong reference.
 @param feedbackDelegate Delegate which `sendFeedbackCompleted(error)` is called on once when the operation completes; if
 error is non-nil, then the operation failed. Stored as a weak reference; the caller is responsible for holding a strong reference.
 @warning Only one active upload is supported at a time. An ongoing upload will be cancelled if this function is called again before it
 completes.
 @warning An ongoing feedback upload started with `startSendFeedback:` should be stopped with `stopSendFeedback` before the
 process exits. This ensures that any underlying resources are cleaned up; failing to do so may result in data store corruption or other
 undefined behavior.
 @warning `PsiphonTunnel.start:` and `startSendFeedback:`  both make an attempt to migrate persistent files from legacy locations in a
 one-time operation. If these functions are called in parallel, then there is a chance that the migration attempts could execute at the same
 time and result in non-fatal errors in one, or both, of the migration operations.
 */
- (void)startSendFeedback:(NSString * _Nonnull)feedbackJson
       feedbackConfigJson:(id _Nonnull)feedbackConfigJson
               uploadPath:(NSString * _Nonnull)uploadPath
           loggerDelegate:(id<PsiphonTunnelLoggerDelegate> _Nullable)loggerDelegate
         feedbackDelegate:(id<PsiphonTunnelFeedbackDelegate> _Nonnull)feedbackDelegate;

/*!
 Interrupt an in-progress feedback upload operation started with `startSendFeedback:`. This call is synchronous and returns once the
 upload has been cancelled.
 */
- (void)stopSendFeedback;

@end
