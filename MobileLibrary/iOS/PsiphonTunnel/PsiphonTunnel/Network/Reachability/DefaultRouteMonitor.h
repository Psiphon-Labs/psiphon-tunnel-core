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
#import <Network/path.h>
#import "ReachabilityProtocol.h"

NS_ASSUME_NONNULL_BEGIN

/// NetworkPathState represents the state of the network path on the device.
@interface NetworkPathState : NSObject

/// Reachability status.
@property (nonatomic, readonly) NetworkReachability status;

/// Network path state.
@property (nonatomic, nullable, readonly) nw_path_t path;

/// Default active interface available to the network path.
@property (nonatomic, nullable, readonly) NSString* defaultActiveInterfaceName;

@end

/// ReachabilityChangedNotification represents the reachability state on the device.
@interface ReachabilityChangedNotification : NSObject

/// Current reachability status.
@property (nonatomic, readonly) NetworkReachability reachabilityStatus;

/// Name of current default active interface. If nil, then there is no such interface.
@property (nonatomic, nullable, readonly) NSString* curDefaultActiveInterfaceName;

/// Name of previous default active interface. If nil, then there was no default active interface previously or the previous default active
/// interface was not capable of sending or receiving network data at the time.
@property (nonatomic, nullable, readonly) NSString* prevDefaultActiveInterfaceName;

@end

/// DefaultRouteMonitor monitors changes to the default route on the device and whether that route is capable of sending and
/// receiving network data.
@interface DefaultRouteMonitor : NSObject <ReachabilityProtocol>

/// Returns the state of the default route on the device. If nil, then there is no usable route available for sending or receiving network data.
@property (atomic, readonly) NetworkPathState *pathState;

- (instancetype)init API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0));

- (id)initWithLogger:(void (^__nonnull)(NSString *_Nonnull))logger API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0));

// Denote ReachabilityProtocol availability.
- (BOOL)startNotifier API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0));
- (void)stopNotifier API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0));
+ (NSString*)reachabilityChangedNotification;
- (NetworkReachability)reachabilityStatus API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0));
- (NSString*)reachabilityStatusDebugInfo API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0));

@end

NS_ASSUME_NONNULL_END
