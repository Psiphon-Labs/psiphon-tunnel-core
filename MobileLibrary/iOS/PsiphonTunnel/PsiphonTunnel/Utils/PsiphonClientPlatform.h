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

NS_ASSUME_NONNULL_BEGIN

@interface PsiphonClientPlatform : NSObject

/// Returns a short description of the platform like "iOS_14.2_unjailbroken_ca.psiphon.Psiphon" if running on iOS
/// or "iOS_13.1_iOSAppOnMac_ca.psiphon.Psiphon" if running as an iOS build on an ARM Mac.
+ (NSString *)getClientPlatform;

@end

NS_ASSUME_NONNULL_END
