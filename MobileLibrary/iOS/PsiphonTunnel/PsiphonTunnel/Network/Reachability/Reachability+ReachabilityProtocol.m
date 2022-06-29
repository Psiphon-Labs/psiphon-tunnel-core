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

#import "Reachability+ReachabilityProtocol.h"

@implementation Reachability (ReachabilityProtocol)

+ (NSString*)reachabilityChangedNotification {
    return kReachabilityChangedNotification;
}

- (NetworkReachability)reachabilityStatus {
    NetworkStatus status = [self currentReachabilityStatus];
    switch (status) {
        case NotReachable:
            return NetworkReachabilityNotReachable;
        case ReachableViaWiFi:
            return NetworkReachabilityReachableViaWiFi;
        case ReachableViaWWAN:
            return NetworkReachabilityReachableViaCellular;
        default:
            [NSException raise:@"unexpected reachability status" format:@"%ld", (long)status];
            return NetworkReachabilityNotReachable;
    }
}

- (NSString*)reachabilityStatusDebugInfo {
    return [self currentReachabilityFlagsToString];
}

@end
