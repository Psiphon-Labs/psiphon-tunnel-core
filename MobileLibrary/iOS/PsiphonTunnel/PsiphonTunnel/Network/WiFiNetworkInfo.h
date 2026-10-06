/*
 * Copyright (c) 2026, Psiphon Inc.
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

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Receives the BSSID of the current Wi-Fi network, or nil if it is unavailable. May be called on any queue.
typedef void (^WiFiNetworkInfoFetchCompletion)(NSString *_Nullable bssid);

/// Fetches the BSSID of the current Wi-Fi network and calls completion exactly once.
typedef void (^WiFiNetworkInfoFetcher)(WiFiNetworkInfoFetchCompletion completion);

/// Builds the network ID of the current Wi-Fi network from bssid, or from a fallback such as the interface address
/// if bssid is nil. Sets *outStable to NO if the network ID must not be kept for the network, for example because
/// no fallback was available. *outStable is YES on entry.
typedef NSString *_Nonnull (^WiFiNetworkIDBuilder)(NSString *_Nullable bssid, BOOL *_Nonnull outStable);

/// WiFiNetworkInfo chooses the network ID of the current Wi-Fi network, using its BSSID when available.
///
/// CNCopyCurrentNetworkInfo returns NULL to apps linked against the iOS 19 SDK or later, regardless of their
/// entitlements (see CaptiveNetwork.h). Its replacement, +[NEHotspotNetwork fetchCurrentWithCompletionHandler:],
/// reports the network asynchronously, on the main queue, but tunnel-core requests the network ID synchronously.
///
/// Tunnel-core requires the network ID to stay the same for as long as the network does: it keys stored tactics and
/// replay parameters by network ID, and discards a tactics response if the network ID changed during the request.
/// So the network ID is chosen once per network, and kept until networkChangedUsingWiFi: or stop is called:
///
/// 1. Each Wi-Fi network begins with one BSSID fetch, which has the timeout to complete.
/// 2. The BSSID is decided by the first of: the fetch completing; a lookup on another thread reaching the timeout;
///    or a lookup on the main thread, which cannot wait for the main queue completion handler. In the last two
///    cases, the decision is that there is no BSSID, and the fetch result is ignored when it arrives.
/// 3. The first lookup after the decision builds the network ID, which is then kept for the network. So a fallback
///    that changes, such as the interface address, does not change the network ID either. A network ID that the
///    builder marks as not stable is not kept.
///
/// NEHotspotNetwork returns nil, without prompting the user, unless the app has the
/// com.apple.developer.networking.wifi-info entitlement and meets one of Apple's conditions, such as having an
/// active VPN configuration installed or precise location authorization. Such an app makes one call per network,
/// and gets the fallback network ID.
///
/// The BSSID is never logged.
@interface WiFiNetworkInfo : NSObject

/// Returns a fetcher that uses +[NEHotspotNetwork fetchCurrentWithCompletionHandler:] on iOS 14 and Mac Catalyst 14
/// and later, and otherwise always completes with nil.
+ (WiFiNetworkInfoFetcher)defaultFetcher;

/// Returns bssid, or nil if it is empty or a placeholder such as 02:00:00:00:00:00, which some platforms report in
/// place of a redacted hardware address. A returned BSSID is unchanged.
+ (NSString *_Nullable)acceptedBSSID:(NSString *_Nullable)bssid;

- (instancetype)init NS_UNAVAILABLE;

/// Uses the default fetcher.
/// @param timeout Time from the start of a network's BSSID fetch after which a lookup decides that there is no
/// BSSID.
/// @param logger Receives diagnostic messages on a private serial queue. May be nil.
- (instancetype)initWithTimeout:(NSTimeInterval)timeout logger:(void (^_Nullable)(NSString *_Nonnull))logger;

/// @param fetcher Fetches the current BSSID.
/// @param timeout Time from the start of a network's BSSID fetch after which a lookup decides that there is no
/// BSSID.
/// @param logger Receives diagnostic messages on a private serial queue. May be nil.
- (instancetype)initWithFetcher:(WiFiNetworkInfoFetcher)fetcher
                        timeout:(NSTimeInterval)timeout
                         logger:(void (^_Nullable)(NSString *_Nonnull))logger NS_DESIGNATED_INITIALIZER;

/// Starts tracking the current network, which begins as with networkChangedUsingWiFi:. Has no effect if already
/// started.
- (void)startUsingWiFi:(BOOL)usesWiFi;

/// Stops tracking the network. Lookups then return nil without waiting, waiting lookups are released, and results
/// of outstanding fetches are discarded.
- (void)stop;

/// Begins a new network, discarding the BSSID and network ID chosen for the previous one. If usesWiFi is YES, then
/// fetches the BSSID; otherwise there is no Wi-Fi network ID. Call only when the network has changed, as the new
/// network may get a different network ID even if it is the same network. Has no effect if not started.
- (void)networkChangedUsingWiFi:(BOOL)usesWiFi;

/// Returns YES if the current network uses Wi-Fi and its BSSID is not decided yet.
- (BOOL)isBSSIDPending;

/// Waits until the BSSID of the current network is decided, deciding that there is none once the timeout passes.
/// If the network changes while waiting, then waits for the BSSID of the new network. Returns immediately if not
/// started, or on the main thread, where waiting would only delay the NEHotspotNetwork completion handler.
- (void)waitForBSSID;

/// Returns the network ID kept for the current Wi-Fi network, using builder to build it if none is kept yet.
/// Returns nil if not started, or if the current network does not use Wi-Fi.
///
/// Before building, waits for the BSSID as waitForBSSID does, except that on the main thread a pending BSSID is
/// decided to be absent. builder is called without any lock held, possibly by several concurrent lookups. The first
/// stable result is kept, and a lookup that finishes building after that returns the kept network ID instead of its
/// own.
- (NSString *_Nullable)networkIDWithBuilder:(NS_NOESCAPE WiFiNetworkIDBuilder)builder;

@end

NS_ASSUME_NONNULL_END
