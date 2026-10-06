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
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <SystemConfiguration/CaptiveNetwork.h>

@implementation NetworkID

// See comment in header.
+ (NSString *)getNetworkIDWithReachability:(id<ReachabilityProtocol>)reachability
                   andCurrentNetworkStatus:(NetworkReachability)currentNetworkStatus
                         tunnelWholeDevice:(BOOL)tunnelWholeDevice
                                 wifiBSSID:(NSString *_Nullable)wifiBSSID
                                   warning:(NSError *_Nullable *_Nonnull)outWarn {

    *outWarn = nil;

    // NetworkID is "VPN" if the library is used in non-VPN mode,
    // and an active VPN is found on the system.
    // This method is not exact and relies on CFNetworkCopySystemProxySettings,
    // specifically it may not return tun interfaces for some VPNs on macOS.
    if (!tunnelWholeDevice) {
        NSDictionary *_Nullable proxies = (__bridge NSDictionary *) CFNetworkCopySystemProxySettings();
        for (NSString *interface in [proxies[@"__SCOPED__"] allKeys]) {
            if ([interface containsString:@"tun"] || [interface containsString:@"tap"] || [interface containsString:@"ppp"] || [interface containsString:@"ipsec"]) {
                return @"VPN";
            }
        }
    }

    NSMutableString *networkID = [NSMutableString stringWithString:@"UNKNOWN"];
    if (currentNetworkStatus == NetworkReachabilityReachableViaWiFi) {
        [networkID setString:@"WIFI"];
#if TARGET_OS_MAC && !TARGET_OS_IPHONE
        NSError *err;
        NSString *activeInterfaceAddress =
            [NetworkInterface getActiveInterfaceAddressWithReachability:reachability
                                                andCurrentNetworkStatus:currentNetworkStatus
                                                                  error:&err];
        if (err != nil) {
            NSString *localizedDescription = [NSString stringWithFormat:@"error getting active interface address %@", err.localizedDescription];
            *outWarn = [[NSError alloc] initWithDomain:@"PsiphonTunnelError"
                                                  code:1
                                              userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
            return networkID;
        }
        [networkID appendFormat:@"-%@", activeInterfaceAddress];
#else
        return [NetworkID wifiNetworkIDWithBSSID:wifiBSSID
                        currentNetworkInfoBSSIDs:^NSArray<NSString *> *{
            return [NetworkID currentNetworkInfoBSSIDs];
        }
                                interfaceAddress:^NSString *(NSError *_Nullable *_Nonnull outError) {
            // As the Android library does with WifiInfo.getIpAddress when it has no BSSID.
            return [NetworkInterface getActiveInterfaceAddressWithReachability:reachability
                                                       andCurrentNetworkStatus:currentNetworkStatus
                                                                         error:outError];
        }
                                         warning:outWarn];
#endif
    } else if (currentNetworkStatus == NetworkReachabilityReachableViaCellular) {
        [networkID setString:@"MOBILE"];

#if TARGET_OS_IOS
        if (@available(iOS 16.0, *)) {
            // Use the active interface address as a best-effort network identifier now that
            // CTCarrier no longer provides useful carrier codes.
            NSError *err;
            NSString *activeInterfaceAddress =
                [NetworkInterface getActiveInterfaceAddressWithReachability:reachability
                                                    andCurrentNetworkStatus:currentNetworkStatus
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
            CTCarrier *cellularProvider = [telephonyNetworkinfo subscriberCellularProvider];
            if (cellularProvider != nil) {
                NSString *mcc = [cellularProvider mobileCountryCode];
                NSString *mnc = [cellularProvider mobileNetworkCode];
                [networkID appendFormat:@"-%@-%@", mcc, mnc];
            }
        }
#endif
    } else if (currentNetworkStatus == NetworkReachabilityReachableViaWired) {
        [networkID setString:@"WIRED"];

        NSError *err;
        NSString *activeInterfaceAddress =
            [NetworkInterface getActiveInterfaceAddressWithReachability:reachability
                                                andCurrentNetworkStatus:currentNetworkStatus
                                                                  error:&err];
        if (err != nil) {
            NSString *localizedDescription = [NSString stringWithFormat:@"error getting active interface address %@", err.localizedDescription];
            *outWarn = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                                  code:1
                                              userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
            return networkID;
        }
        [networkID appendFormat:@"-%@", activeInterfaceAddress];
    } else if (currentNetworkStatus == NetworkReachabilityReachableViaLoopback) {
        [networkID setString:@"LOOPBACK"];
    }
    return networkID;
}

// See comment in header.
+ (NSString *)wifiNetworkIDWithBSSID:(NSString *_Nullable)wifiBSSID
            currentNetworkInfoBSSIDs:(NetworkIDCurrentNetworkInfoBSSIDs)currentNetworkInfoBSSIDs
                    interfaceAddress:(NetworkIDInterfaceAddress)interfaceAddress
                             warning:(NSError *_Nullable *_Nonnull)outWarn {

    *outWarn = nil;

    if (wifiBSSID.length > 0) {
        return [@"WIFI-" stringByAppendingString:wifiBSSID];
    }

    NSArray<NSString *> *bssids = currentNetworkInfoBSSIDs();
    if (bssids.count > 0) {
        return [@"WIFI-" stringByAppendingString:[bssids componentsJoinedByString:@"-"]];
    }

    NSError *err;
    NSString *activeInterfaceAddress = interfaceAddress(&err);
    if (err != nil || activeInterfaceAddress.length == 0) {
        NSString *localizedDescription = [NSString stringWithFormat:@"error getting active interface address %@",
                                          err != nil ? err.localizedDescription : @"empty address"];
        *outWarn = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                              code:1
                                          userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
        return @"WIFI";
    }
    return [@"WIFI-" stringByAppendingString:activeInterfaceAddress];
}

#if TARGET_OS_IPHONE
+ (NSArray<NSString *> *)currentNetworkInfoBSSIDs {
    NSMutableArray<NSString *> *bssids = [NSMutableArray array];
    NSArray *networkInterfaceNames = (__bridge_transfer id)CNCopySupportedInterfaces();
    for (NSString *networkInterfaceName in networkInterfaceNames) {
        NSDictionary *networkInterfaceInfo = (__bridge_transfer id)CNCopyCurrentNetworkInfo((__bridge CFStringRef)networkInterfaceName);
        id bssid = networkInterfaceInfo[(__bridge NSString*)kCNNetworkInfoKeyBSSID];
        if ([bssid isKindOfClass:[NSString class]] && [bssid length] > 0) {
            [bssids addObject:bssid];
        }
    }
    return bssids;
}
#endif

@end
