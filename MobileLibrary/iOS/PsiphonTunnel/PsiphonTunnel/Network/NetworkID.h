/*
 * Copyright (c) 2020, Psiphon Inc.
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
#import "ReachabilityProtocol.h"

NS_ASSUME_NONNULL_BEGIN

@interface NetworkID : NSObject

/// The network ID contains potential PII. In tunnel-core, the network ID
/// is used only locally in the client and not sent to the server.
///
/// See network ID requirements here:
/// https://godoc.org/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon#NetworkIDGetter
/// @param reachability ReachabilityProtocol implementer used to determine active interface on iOS >=12 when
/// currentNetworkStatus is NetworkReachabilityReachableViaWired.
/// @param currentNetworkStatus Used to determine network ID and, on iOS <12, to determine the active interface when
/// currentNetworkStatus is NetworkReachabilityReachableViaWired.
/// @param outWarn If non-nil, then a non-fatal error occurred while determining the network ID and a valid network ID will still be returned.
+ (NSString *)getNetworkIDWithReachability:(id<ReachabilityProtocol>)reachability
                   andCurrentNetworkStatus:(NetworkReachability)currentNetworkStatus
                                   warning:(NSError *_Nullable *_Nonnull)outWarn;

@end

NS_ASSUME_NONNULL_END
