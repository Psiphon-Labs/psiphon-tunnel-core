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

/// WiFiNetworkInfo provides the BSSID of the current Wi-Fi network for the network ID.
///
/// CNCopyCurrentNetworkInfo returns NULL to apps linked against the iOS 19 SDK or later, regardless of their
/// entitlements (see CaptiveNetwork.h). Its replacement, +[NEHotspotNetwork fetchCurrentWithCompletionHandler:],
/// reports the network asynchronously, on the main queue, but tunnel-core requests the network ID synchronously.
/// So the BSSID is fetched ahead of time and cached: when started, whenever the network path changes, and
/// whenever invalidateAndRefetch is called. A lookup made while a fetch is outstanding waits for it, up to a
/// timeout.
///
/// NEHotspotNetwork returns nil, without prompting the user, unless the app has the
/// com.apple.developer.networking.wifi-info entitlement and meets one of Apple's conditions, such as having an
/// active VPN configuration installed or precise location authorization. A nil result is cached like a BSSID, so
/// such an app makes one call per network path change rather than one per network ID lookup.
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

/// Uses the default fetcher and monitors the network path once started.
/// @param logger Receives diagnostic messages on a private serial queue. May be nil.
- (instancetype)initWithLogger:(void (^_Nullable)(NSString *_Nonnull))logger;

/// @param fetcher Fetches the current BSSID.
/// @param monitorsPath If YES, start monitors the network path and calls pathUpdatedUsingWiFi: on each update.
/// If NO, the caller is responsible for calling pathUpdatedUsingWiFi:.
/// @param logger Receives diagnostic messages on a private serial queue. May be nil.
- (instancetype)initWithFetcher:(WiFiNetworkInfoFetcher)fetcher
                   monitorsPath:(BOOL)monitorsPath
                         logger:(void (^_Nullable)(NSString *_Nonnull))logger NS_DESIGNATED_INITIALIZER;

/// Marks the BSSID as pending and starts monitoring the network path, if configured to. The first path update
/// fetches the BSSID. Has no effect if already started.
- (void)start;

/// Stops monitoring the network path and clears the cached BSSID. Lookups then return nil without waiting, and
/// results of outstanding fetches are discarded.
- (void)stop;

/// Discards the cached BSSID and fetches it again. Call when the network may have changed. Has no effect if not
/// started.
- (void)invalidateAndRefetch;

/// Handles a network path update. If the path uses Wi-Fi, the cached BSSID is discarded and fetched again.
/// Otherwise, the cached BSSID is cleared without a fetch. Has no effect if not started.
- (void)pathUpdatedUsingWiFi:(BOOL)usesWiFi;

/// Returns the cached BSSID of the current Wi-Fi network, or nil if there is none.
///
/// If a fetch is outstanding, waits up to timeout for it to complete. Once a wait for the current result times
/// out, later lookups return nil without waiting until that result arrives or the BSSID is invalidated. Never
/// waits on the main thread, where the NEHotspotNetwork completion handler runs.
- (NSString *_Nullable)bssidWaitingUpTo:(NSTimeInterval)timeout;

@end

NS_ASSUME_NONNULL_END
