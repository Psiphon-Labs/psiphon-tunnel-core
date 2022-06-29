/*
 * Copyright (c) 2021, Psiphon Inc.
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

typedef enum : NSInteger {
    NetworkReachabilityNotReachable = 0,
    NetworkReachabilityReachableViaWiFi,
    NetworkReachabilityReachableViaCellular,
    NetworkReachabilityReachableViaWired,
    NetworkReachabilityReachableViaLoopback,
    NetworkReachabilityReachableViaUnknown
} NetworkReachability;

NS_ASSUME_NONNULL_BEGIN

/// ReachabilityProtocol is a protocol for monitoring the reachability of a target network destination. For example, a protocol
/// implementation could provide reachability information for the default gateway over a specific network interface.
/// @note The purpose of ReachabilityProtocol is to bridge the gap between Apple's old Reachability APIs and the new
/// NWPathMonitor (iOS 12.0+) with a common interface that allows each to be used interchangeably. Using a common interface
/// simplifies supporting older clients which cannot target NWPathMonitor until the minimum iOS target is 12.0+, at which point the
/// code targeting the legacy Reachability APIs can be removed.
@protocol ReachabilityProtocol <NSObject>

/// Name of reachability notifications emitted from the default notification center. See comment for `startNotifier`.
+ (NSString*)reachabilityChangedNotification;

/// Start listening for reachability changes. A notification with the name returned by `reachabilityChangedNotification` will be emitted
/// from the default notification center until `stopNotifier` is called.
- (BOOL)startNotifier;

/// Stop listening for reachability changes.
- (void)stopNotifier;

/// Return current reachability status.
- (NetworkReachability)reachabilityStatus;

/// Return debug string which represents the current network state for logging.
- (NSString*)reachabilityStatusDebugInfo;

@end

NS_ASSUME_NONNULL_END
