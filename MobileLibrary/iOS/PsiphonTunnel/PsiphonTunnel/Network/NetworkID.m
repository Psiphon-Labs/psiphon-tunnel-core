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
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <SystemConfiguration/CaptiveNetwork.h>

@implementation NetworkID

+ (NSString *)getNetworkID:(NetworkStatus)networkStatus {

    NSMutableString *networkID = [NSMutableString stringWithString:@"UNKNOWN"];
    if (networkStatus == ReachableViaWiFi) {
        [networkID setString:@"WIFI"];
        NSArray *networkInterfaceNames = (__bridge_transfer id)CNCopySupportedInterfaces();
        for (NSString *networkInterfaceName in networkInterfaceNames) {
            NSDictionary *networkInterfaceInfo = (__bridge_transfer id)CNCopyCurrentNetworkInfo((__bridge CFStringRef)networkInterfaceName);
            if (networkInterfaceInfo[@"BSSID"]) {
                [networkID appendFormat:@"-%@", networkInterfaceInfo[@"BSSID"]];
            }
        }
    } else if (networkStatus == ReachableViaWWAN) {
        [networkID setString:@"MOBILE"];
        CTTelephonyNetworkInfo *telephonyNetworkinfo = [[CTTelephonyNetworkInfo alloc] init];
        CTCarrier *cellularProvider = [telephonyNetworkinfo subscriberCellularProvider];
        if (cellularProvider != nil) {
            NSString *mcc = [cellularProvider mobileCountryCode];
            NSString *mnc = [cellularProvider mobileNetworkCode];
            [networkID appendFormat:@"-%@-%@", mcc, mnc];
        }
    }
    return networkID;
}

@end
