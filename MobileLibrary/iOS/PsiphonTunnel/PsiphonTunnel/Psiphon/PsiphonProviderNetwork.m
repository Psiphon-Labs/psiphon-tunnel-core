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

#import "PsiphonProviderNetwork.h"
#import "IPv6Synthesizer.h"
#import "Reachability.h"
#import "Reachability+HasNetworkConnectivity.h"
#import "NetworkID.h"

@implementation PsiphonProviderNetwork {
    Reachability *reachability;
}

- (id)init {
    self = [super init];
    if (self) {
        self->reachability = [Reachability reachabilityForInternetConnection];
    }
    return self;
}

- (long)hasNetworkConnectivity {
    return [self->reachability hasNetworkConnectivity];
}


- (NSString *)iPv6Synthesize:(NSString *)IPv4Addr {
    return [IPv6Synthesizer IPv4ToIPv6:IPv4Addr];
}

- (NSString *)getNetworkID {
    return [NetworkID getNetworkID:reachability.currentReachabilityStatus];
}

@end
