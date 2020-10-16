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

#import "IPv6Synthesizer.h"
#import "LookupIPv6.h"

@implementation IPv6Synthesizer

+ (NSString *)IPv4ToIPv6:(NSString *)IPv4Addr {
    char *result = getIPv6ForIPv4([IPv4Addr UTF8String]);
    if (result != NULL) {
        NSString *IPv6Addr = [NSString stringWithUTF8String:result];
        free(result);
        return IPv6Addr;
    }
    return @"";
}

@end
