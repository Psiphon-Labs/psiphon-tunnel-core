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

#import "NetworkInterface.h"

#import <net/if.h>
#import <ifaddrs.h>
#import <netdb.h>
#import <netinet/in.h>
#import <Network/Network.h>
#import "DefaultRouteMonitor.h"

static uint32_t IPv6First32Bits(const struct in6_addr *addr) {
    const uint8_t *b = addr->s6_addr;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

// See comment in header.
NSString *NetworkInterfaceFormatIPv6Prefix(const struct in6_addr *addr) {
    uint32_t prefix = IPv6First32Bits(addr);
    return [NSString stringWithFormat:@"%x:%x::/32", (unsigned int)(prefix >> 16), (unsigned int)(prefix & 0xffff)];
}

// See comment in header.
const struct ifaddrs *_Nullable NetworkInterfaceSelectAddress(const struct ifaddrs *_Nullable interfaces,
                                                              const char *_Nullable interfaceName) {
    if (interfaceName == NULL) {
        return NULL;
    }

    const struct ifaddrs *bestIPv6 = NULL;
    BOOL bestIsUniqueLocal = NO;
    uint32_t bestPrefix = 0;

    for (const struct ifaddrs *interface = interfaces; interface != NULL; interface = interface->ifa_next) {

        // Only IFF_UP interfaces. Loopback is ignored.
        if (!(interface->ifa_flags & IFF_UP) || (interface->ifa_flags & IFF_LOOPBACK)) {
            continue;
        }

        const struct sockaddr *addr = interface->ifa_addr;
        if (addr == NULL || (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)) {
            continue;
        }

        // ifa_name could be NULL
        // https://sourceware.org/bugzilla/show_bug.cgi?id=21812
        if (interface->ifa_name == NULL || strcmp(interface->ifa_name, interfaceName) != 0) {
            continue;
        }

        if (addr->sa_family == AF_INET) {
            // Skip IPv4 addresses that do not identify the network:
            // - self-assigned link-local, 169.254.0.0/16
            // - 464XLAT, 192.0.0.0/29 (RFC 7335); the same address, typically 192.0.0.2,
            //   is used on every IPv6-only network that provides IPv4 by translation
            in_addr_t addr4 = ntohl(((const struct sockaddr_in *)addr)->sin_addr.s_addr);
            if (IN_LINKLOCAL(addr4) || (addr4 & 0xfffffff8) == 0xc0000000) {
                continue;
            }
            return interface;
        }

        // Only the first 32 bits of an IPv6 address are used in the network ID: a coarse value that stays the
        // same on a network is preferred over a precise one that changes on it, as full addresses do with the
        // delegated prefix and privacy address rotation. Unique local (fc00::/7) is preferred over global
        // unicast (2000::/3) because the local router chooses it, so it survives ISP prefix changes. Taking
        // the lowest prefix makes the result independent of list order. Other ranges are ignored.
        uint32_t prefix = IPv6First32Bits(&((const struct sockaddr_in6 *)addr)->sin6_addr);
        BOOL isUniqueLocal = (prefix & 0xfe000000) == 0xfc000000;
        BOOL isGlobal = (prefix & 0xe0000000) == 0x20000000;
        if (!isUniqueLocal && !isGlobal) {
            continue;
        }
        if (bestIPv6 == NULL ||
            (isUniqueLocal && !bestIsUniqueLocal) ||
            (isUniqueLocal == bestIsUniqueLocal && prefix < bestPrefix)) {
            bestIPv6 = interface;
            bestIsUniqueLocal = isUniqueLocal;
            bestPrefix = prefix;
        }
    }

    return bestIPv6;
}

@implementation NetworkInterface

+ (NSString*_Nullable)getInterfaceAddress:(NSString*_Nonnull)interfaceName
                                    error:(NSError *_Nullable *_Nonnull)outError {
    *outError = nil;

    struct ifaddrs *interfaces;
    if (getifaddrs(&interfaces) != 0) {
        NSString *localizedDescription = [NSString stringWithFormat:@"getifaddrs error with errno %d", errno];
        *outError = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                               code:1
                                           userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
        return nil;
    }

    const struct ifaddrs *interface = NetworkInterfaceSelectAddress(interfaces,
                                                                    [interfaceName UTF8String]);
    if (interface == NULL) {
        freeifaddrs(interfaces);
        return nil;
    }

    if (interface->ifa_addr->sa_family == AF_INET6) {
        NSString *prefix =
            NetworkInterfaceFormatIPv6Prefix(&((const struct sockaddr_in6 *)interface->ifa_addr)->sin6_addr);
        freeifaddrs(interfaces);
        return prefix;
    }

    char addr[NI_MAXHOST];
    int ret = getnameinfo(interface->ifa_addr,
                          (socklen_t)interface->ifa_addr->sa_len,
                          addr,
                          (socklen_t)NI_MAXHOST,
                          NULL,
                          (socklen_t)0,
                          NI_NUMERICHOST);

    freeifaddrs(interfaces);

    if (ret != 0) {
        NSString *localizedDescription = [NSString stringWithFormat:@"getnameinfo returned %d", ret];
        *outError = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                               code:1
                                           userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
        return nil;
    }

    return [NSString stringWithUTF8String:addr];
}

+ (NSSet<NSString*>*)activeInterfaces:(NSError *_Nullable *_Nonnull)outError {

    *outError = nil;

    NSMutableSet *upIffList = [NSMutableSet new];

    struct ifaddrs *interfaces;
    if (getifaddrs(&interfaces) != 0) {
        NSString *localizedDescription = [NSString stringWithFormat:@"getifaddrs error with errno %d", errno];
        *outError = [[NSError alloc] initWithDomain:@"iOSLibrary" code:1 userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
        return upIffList;
    }

    struct ifaddrs *interface;
    for (interface=interfaces; interface; interface=interface->ifa_next) {

        // Only IFF_UP interfaces. Loopback is ignored.
        if (interface->ifa_flags & IFF_UP && !(interface->ifa_flags & IFF_LOOPBACK)) {

            if (interface->ifa_addr && (interface->ifa_addr->sa_family==AF_INET || interface->ifa_addr->sa_family==AF_INET6)) {

                // ifa_name could be NULL
                // https://sourceware.org/bugzilla/show_bug.cgi?id=21812
                if (interface->ifa_name != NULL) {
                    NSString *interfaceName = [NSString stringWithUTF8String:interface->ifa_name];
                    [upIffList addObject:interfaceName];
                }
            }
        }
    }

    // Free getifaddrs data
    freeifaddrs(interfaces);

    return upIffList;
}

/*!
 @brief Returns name of default active network interface from the provided list of active interfaces.
 @param upIffList List of active network interfaces.
 @return Active interface name, nil otherwise.
 @warning Use DefaultRouteMonitor instead on iOS 12.0+.
 */
+ (NSString *)getActiveInterface:(NSSet<NSString*>*)upIffList
            currentNetworkStatus:(NetworkReachability)currentNetworkStatus {

    // TODO: following is a heuristic for choosing active network interface
    // Only Wi-Fi and Cellular interfaces are considered
    // @see : https://forums.developer.apple.com/thread/76711
    NSArray *iffPriorityList = @[@"en0", @"pdp_ip0"];
    if (currentNetworkStatus == NetworkReachabilityReachableViaCellular) {
        iffPriorityList = @[@"pdp_ip0", @"en0"];
    }
    for (NSString * key in iffPriorityList) {
        for (NSString * upIff in upIffList) {
            if ([key isEqualToString:upIff]) {
                return [NSString stringWithString:upIff];
            }
        }
    }

    return nil;
}

+ (NSString*)getActiveInterfaceWithPathState:(NetworkPathState *_Nullable)pathState
                     andCurrentNetworkStatus:(NetworkReachability)currentNetworkStatus
                                       error:(NSError *_Nullable *_Nonnull)outError {

    *outError = nil;

    NSString *activeInterface;

    if (@available(iOS 12.0, *)) {
        // Note: pathState is a snapshot, and DefaultRouteMonitor may observe a new path after it was taken.
        // The interface returned may then no longer be active, and its address, read later, may have changed
        // or be missing.
        if (pathState == nil) {
            *outError = [[NSError alloc] initWithDomain:@"iOSLibrary" code:1 userInfo:@{NSLocalizedDescriptionKey: @"getActiveInterfaceWithPathState: network path state nil"}];
            return @"";
        }
        // Note: could fallback on heuristic for iOS <12.0 if nil
        activeInterface = pathState.defaultActiveInterfaceName;
    } else {
        // Limitation: currentNetworkStatus and the interface heuristic below are not taken from one observation,
        // so during a handoff the network ID can briefly pair the type of one network with the address of another.
        NSError *err;
        NSSet<NSString*>* upIffList = [NetworkInterface activeInterfaces:&err];
        if (err != nil) {
            NSString *localizedDescription = [NSString stringWithFormat:@"getActiveInterfaceWithPathState: error getting active interfaces %@", err.localizedDescription];
            *outError = [[NSError alloc] initWithDomain:@"iOSLibrary" code:1 userInfo:@{NSLocalizedDescriptionKey: localizedDescription}];
            return @"";
        }
        if (upIffList == nil) {
            *outError = [[NSError alloc] initWithDomain:@"iOSLibrary" code:1 userInfo:@{NSLocalizedDescriptionKey: @"getActiveInterfaceWithPathState: no active interfaces"}];
            return @"";
        }
        activeInterface = [NetworkInterface getActiveInterface:upIffList
                                          currentNetworkStatus:currentNetworkStatus];
    }

    if (activeInterface == nil) {
        *outError = [[NSError alloc] initWithDomain:@"iOSLibrary" code:1 userInfo:@{NSLocalizedDescriptionKey: @"getActiveInterfaceWithPathState: no active interface"}];
        return @"";
    }

    return activeInterface;
}

+ (NSString*)getActiveInterfaceAddressWithPathState:(NetworkPathState *_Nullable)pathState
                            andCurrentNetworkStatus:(NetworkReachability)currentNetworkStatus
                                              error:(NSError *_Nullable *_Nonnull)outError {

    *outError = nil;

    NSError *err;
    NSString *activeInterface =
        [NetworkInterface getActiveInterfaceWithPathState:pathState
                                  andCurrentNetworkStatus:currentNetworkStatus
                                                    error:&err];
    if (err != nil) {
        NSString *localizedDescription = [NSString stringWithFormat:@"error getting active interface %@", err.localizedDescription];
        *outError = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                               code:1
                                           userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
        return @"";
    } else if (activeInterface == nil) {
        NSString *localizedDescription = @"active interface nil";
        *outError = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                               code:1
                                           userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
        return @"";
    }

    NSString *interfaceAddress = [NetworkInterface getInterfaceAddress:activeInterface
                                                                 error:&err];
    if (err != nil) {
        NSString *localizedDescription =
            [NSString stringWithFormat:@"error getting interface address %@", err.localizedDescription];
        *outError = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                               code:1
                                           userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
        return @"";
    } else if (interfaceAddress == nil) {
        NSString *localizedDescription = @"interface address nil";
        *outError = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                               code:1
                                           userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
        return @"";
    }

    return interfaceAddress;
}

@end
