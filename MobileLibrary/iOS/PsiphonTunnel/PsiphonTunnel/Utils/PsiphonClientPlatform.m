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
    // Like "iOS". Older iOS reports "iPhone OS", which we will convert.
    NSString *systemName = [[UIDevice currentDevice] systemName];

    if ([systemName isEqual: @"iPhone OS"]) {
        systemName = @"iOS";
    }
    systemName = [[systemName
                   stringByReplacingOccurrencesOfString:@"_" withString:@"-"]
                  stringByReplacingOccurrencesOfString:@" " withString:@"-"];

    // Like "10.2.1"
    NSString *systemVersion = [[[[UIDevice currentDevice]systemVersion]
                                stringByReplacingOccurrencesOfString:@"_" withString:@"-"]
                               stringByReplacingOccurrencesOfString:@" " withString:@"-"];

    // The value of this property is YES only when the process is an iOS app running on a Mac.
    // The value of the property is NO for all other apps on the Mac, including Mac apps built
    // using Mac Catalyst. The property is also NO for processes running on platforms other than macOS.
    BOOL isiOSAppOnMac = FALSE;
    if (@available(iOS 14.0, *)) {
        isiOSAppOnMac = [[NSProcessInfo processInfo] isiOSAppOnMac];
    }

    // The value of this property is true when the process is:
    // - A Mac app built with Mac Catalyst, or an iOS app running on Apple silicon.
    // - Running on a Mac.
    BOOL isMacCatalystApp = FALSE;
    if (@available(iOS 14.0, *)) {
        isMacCatalystApp = [[NSProcessInfo processInfo] isMacCatalystApp];
    }

    // Possible values are: "unjailbroken"/"jailbroken"/"iOSAppOnMac"/"MacCatalystApp"
    // Note that on Macs, users have root access, unlike iOS, where
    // the user has to jailbreak the device to get root access.
    NSString *detail = @"unjailbroken";

    if (isiOSAppOnMac == TRUE && isMacCatalystApp == TRUE) {
        detail = @"iOSAppOnMac";
    } else if (isiOSAppOnMac == FALSE && isMacCatalystApp == TRUE) {
        detail = @"MacCatalystApp";
    } else {
        // App is an iOS app running on iOS.
        if ([JailbreakCheck isDeviceJailbroken] == TRUE) {
            detail = @"jailbroken";
        }
    }

    // Like "com.psiphon3.browser"
    NSString *bundleIdentifier = [[[[NSBundle mainBundle] bundleIdentifier]
                                   stringByReplacingOccurrencesOfString:@"_" withString:@"-"]
                                  stringByReplacingOccurrencesOfString:@" " withString:@"-"];

    NSString *clientPlatform = [NSString stringWithFormat:@"%@_%@_%@_%@",
                                systemName,
                                systemVersion,
                                detail,
                                bundleIdentifier];

    return clientPlatform;
}

@end
