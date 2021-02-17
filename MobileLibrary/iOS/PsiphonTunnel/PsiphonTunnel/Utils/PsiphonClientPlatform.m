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

#import "PsiphonClientPlatform.h"
#import <UIKit/UIKit.h>
#import "JailbreakCheck.h"

@implementation PsiphonClientPlatform

+ (NSString *)getClientPlatform {
    // ClientPlatform must not contain:
    //   - underscores, which are used by us to separate the constituent parts
    //   - spaces, which are considered invalid by the server


    // The value of this property is YES only when the process is an iOS app running on a Mac.
    // The value of the property is NO for all other apps on the Mac, including Mac apps built
    // using Mac Catalyst. The property is also NO for processes running on platforms other than macOS.
    BOOL isiOSAppOnMac = FALSE;
    if (@available(iOS 14.0, *)) {
        isiOSAppOnMac = [[NSProcessInfo processInfo] isiOSAppOnMac];
    }

    // Like "10.2.1"
    NSString *systemVersion = [[[[UIDevice currentDevice]systemVersion]
                                stringByReplacingOccurrencesOfString:@"_" withString:@"-"]
                               stringByReplacingOccurrencesOfString:@" " withString:@"-"];

    // Like "com.psiphon3.browser"
    NSString *bundleIdentifier = [[[[NSBundle mainBundle] bundleIdentifier]
                                   stringByReplacingOccurrencesOfString:@"_" withString:@"-"]
                                  stringByReplacingOccurrencesOfString:@" " withString:@"-"];


    if (isiOSAppOnMac == TRUE) {

        // iOS app running on ARM Mac.

        NSString *systemName = @"mac_iOSAppOnMac";

        return [NSString stringWithFormat:@"%@_%@_%@",
                systemName,
                systemVersion,
                bundleIdentifier];


    } else {

        // iOS build running on iOS device.

        // Like "iOS". Older iOS reports "iPhone OS", which we will convert.
        NSString *systemName = [[UIDevice currentDevice] systemName];

        if ([systemName isEqual: @"iPhone OS"]) {
            systemName = @"iOS";
        }
        systemName = [[systemName
                       stringByReplacingOccurrencesOfString:@"_" withString:@"-"]
                      stringByReplacingOccurrencesOfString:@" " withString:@"-"];

        // Note that on Macs, users have root access, unlike iOS, where
        // the user has to jailbreak the device to get root access.
        NSString *jailbroken = nil;
        if ([JailbreakCheck isDeviceJailbroken] == TRUE) {
            jailbroken = @"jailbroken";
        } else {
            jailbroken = @"unjailbroken";
        }

        return [NSString stringWithFormat:@"%@_%@_%@_%@",
                systemName,
                systemVersion,
                jailbroken,
                bundleIdentifier];

    }

}

@end
