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

#import "NetworkID.h"
#import "NetworkInterface.h"
#import "DefaultRouteMonitor.h"
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>

@implementation NetworkID

// See comment in header.
+ (NSString *)getNetworkIDWithReachability:(id<ReachabilityProtocol>)reachability
                   andCurrentNetworkStatus:(NetworkReachability)currentNetworkStatus
                         tunnelWholeDevice:(BOOL)tunnelWholeDevice
                                   warning:(NSError *_Nullable *_Nonnull)outWarn {

    *outWarn = nil;

    // NetworkID is "VPN" if the library is used in non-VPN mode,
    // and an active VPN is found on the system.
    // This method is not exact and relies on CFNetworkCopySystemProxySettings,
    // specifically it may not return tun interfaces for some VPNs on macOS.
    if (!tunnelWholeDevice) {
        NSDictionary *_Nullable proxies = (__bridge_transfer NSDictionary *) CFNetworkCopySystemProxySettings();
        for (NSString *interface in [proxies[@"__SCOPED__"] allKeys]) {
            if ([interface containsString:@"tun"] || [interface containsString:@"tap"] || [interface containsString:@"ppp"] || [interface containsString:@"ipsec"]) {
                return @"VPN";
            }
        }
    }

    // Take the network type and the active interface name from one observation of the monitor. currentNetworkStatus
    // is updated only after the monitor's reachability notification is delivered, so during a handoff it can be
    // the previous network's type while the monitor already reports the new network's interface. The interface's
    // address is read later and is not part of that observation.
    NetworkReachability networkStatus = currentNetworkStatus;
    NetworkPathState *_Nullable pathState = nil;
    if (@available(iOS 12.0, *)) {
        pathState = [(DefaultRouteMonitor *)reachability pathState];
        if (pathState != nil) {
            networkStatus = pathState.status;
        }
    }

    NSMutableString *networkID = [NSMutableString stringWithString:@"UNKNOWN"];
    if (networkStatus == NetworkReachabilityReachableViaWiFi) {
        [networkID setString:@"WIFI"];

        // The access point's hardware address is deliberately not used: it identifies a single access point radio,
        // not the network, so one network with several access points or bands would get several network IDs.
        NSError *err;
        NSString *activeInterfaceAddress =
            [NetworkInterface getActiveInterfaceAddressWithPathState:pathState
                                             andCurrentNetworkStatus:networkStatus
                                                               error:&err];
        if (err != nil) {
            NSString *localizedDescription = [NSString stringWithFormat:@"error getting active interface address %@", err.localizedDescription];
            *outWarn = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                                  code:1
                                              userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
            return networkID;
        }
        [networkID appendFormat:@"-%@", activeInterfaceAddress];
    } else if (networkStatus == NetworkReachabilityReachableViaCellular) {
        [networkID setString:@"MOBILE"];

#if TARGET_OS_IOS
        if (@available(iOS 16.0, *)) {
            // Use the active interface address as a best-effort network identifier now that
            // CTCarrier no longer provides useful carrier codes.
            NSError *err;
            NSString *activeInterfaceAddress =
                [NetworkInterface getActiveInterfaceAddressWithPathState:pathState
                                                 andCurrentNetworkStatus:networkStatus
                                                                   error:&err];
            if (err != nil) {
                NSString *localizedDescription = [NSString stringWithFormat:@"error getting active interface address %@", err.localizedDescription];
                *outWarn = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                                      code:1
                                                  userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
                return networkID;
            }
            [networkID appendFormat:@"-%@", activeInterfaceAddress];
        } else {
            // CTCarrier.mobileCountryCode and CTCarrier.mobileCountryCode deprecated
            // without replacement in iOS 16.0 https://developer.apple.com/forums/thread/714876.
            CTTelephonyNetworkInfo *telephonyNetworkinfo = [[CTTelephonyNetworkInfo alloc] init];
            // subscriberCellularProvider is deprecated since iOS 12.0, but is still used before iOS 16.0.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            CTCarrier *cellularProvider = [telephonyNetworkinfo subscriberCellularProvider];
#pragma clang diagnostic pop
            if (cellularProvider != nil) {
                NSString *mcc = [cellularProvider mobileCountryCode];
                NSString *mnc = [cellularProvider mobileNetworkCode];
                [networkID appendFormat:@"-%@-%@", mcc, mnc];
            }
        }
#endif
    } else if (networkStatus == NetworkReachabilityReachableViaWired) {
        [networkID setString:@"WIRED"];

        NSError *err;
        NSString *activeInterfaceAddress =
            [NetworkInterface getActiveInterfaceAddressWithPathState:pathState
                                             andCurrentNetworkStatus:networkStatus
                                                               error:&err];
        if (err != nil) {
            NSString *localizedDescription = [NSString stringWithFormat:@"error getting active interface address %@", err.localizedDescription];
            *outWarn = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                                  code:1
                                              userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
            return networkID;
        }
        [networkID appendFormat:@"-%@", activeInterfaceAddress];
    } else if (networkStatus == NetworkReachabilityReachableViaLoopback) {
        [networkID setString:@"LOOPBACK"];
    }
    return networkID;
}

@end
