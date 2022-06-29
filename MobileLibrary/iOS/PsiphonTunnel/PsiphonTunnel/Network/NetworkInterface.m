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
#import <netinet6/in6.h>
#import <Network/path.h>
#import <Network/path_monitor.h>
#import "DefaultRouteMonitor.h"

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

    struct ifaddrs *interface;
    for (interface=interfaces; interface; interface=interface->ifa_next) {

        // Only IFF_UP interfaces. Loopback is ignored.
        if (interface->ifa_flags & IFF_UP && !(interface->ifa_flags & IFF_LOOPBACK)) {

            if (interface->ifa_addr && (interface->ifa_addr->sa_family==AF_INET || interface->ifa_addr->sa_family==AF_INET6)) {

                // ifa_name could be NULL
                // https://sourceware.org/bugzilla/show_bug.cgi?id=21812
                if (interface->ifa_name != NULL) {

                    NSString *curInterfaceName = [NSString stringWithUTF8String:interface->ifa_name];
                    if ([interfaceName isEqualToString:curInterfaceName]) {

                        // Ignore IPv6 link-local addresses https://developer.apple.com/forums/thread/128215?answerId=403310022#403310022
                        // Do not ignore link-local IPv4 addresses because it is possible the interface
                        // is assigned one manually, or if DHCP fails, etc.
                        if (interface->ifa_addr->sa_family == AF_INET6) {
                            struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6*)interface->ifa_addr;
                            if (sa_in6 != NULL) {
                                struct in6_addr i_a = sa_in6->sin6_addr;
                                if (IN6_IS_ADDR_LINKLOCAL(&i_a)) {
                                    // TODO: consider excluding other IP ranges
                                    continue;
                                }
                            }
                        }

                        char addr[NI_MAXHOST];
                        int ret = getnameinfo(interface->ifa_addr,
                                              (socklen_t)interface->ifa_addr->sa_len,
                                              addr,
                                              (socklen_t)NI_MAXHOST,
                                              NULL,
                                              (socklen_t)0,
                                              NI_NUMERICHOST);
                        if (ret != 0) {
                            NSString *localizedDescription = [NSString stringWithFormat:@"getnameinfo returned %d", ret];
                            *outError = [[NSError alloc] initWithDomain:@"iOSLibrary"
                                                                   code:1
                                                               userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
                            freeifaddrs(interfaces);
                            return nil;
                        }

                        freeifaddrs(interfaces);

                        NSString *resolvedAddr = [NSString stringWithUTF8String:addr];

                        return resolvedAddr;
                    }
                }
            }
        }
    }

    freeifaddrs(interfaces);

    return nil;
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

+ (NSString*)getActiveInterfaceWithReachability:(id<ReachabilityProtocol>)reachability
                        andCurrentNetworkStatus:(NetworkReachability)currentNetworkStatus
                                          error:(NSError *_Nullable *_Nonnull)outError {

    *outError = nil;

    NSString *activeInterface;

    if (@available(iOS 12.0, *)) {
        // Note: it is hypothetically possible that NWPathMonitor emits a new path after
        // getActiveInterfaceWithReachability is called. This creates a race between
        // DefaultRouteMonitor updating its internal state and getActiveInterfaceWithReachability
        // retrieving the active interface from that internal state.
        // Therefore the following sequence of events is possible:
        // - NWPathMonitor emits path that is satisfied or satisfiable
        // - ReachabilityProtocol consumer sees there is connectivity and calls
        //   getActiveInterfaceWithReachability
        // - NWPathMonitor emits path that is unsatisfied or invalid
        // - getActiveInterfaceWithReachability either: a) does not observe update and returns the
        //   previously active interface; or b) observes update and cannot find active interface.
        // In both scenarios the reachability state will change to unreachable and it is up to the
        // consumer to call getActiveInterfaceWithReachability again once it becomes reachable again.
        DefaultRouteMonitor *gwMonitor = (DefaultRouteMonitor*)reachability;
        if (gwMonitor == nil) {
            *outError = [[NSError alloc] initWithDomain:@"iOSLibrary" code:1 userInfo:@{NSLocalizedDescriptionKey: @"getActiveInterfaceWithReachability: DefaultRouteMonitor nil"}];
            return @"";
        }
        NetworkPathState *state = [gwMonitor pathState];
        if (state == nil) {
            *outError = [[NSError alloc] initWithDomain:@"iOSLibrary" code:1 userInfo:@{NSLocalizedDescriptionKey: @"getActiveInterfaceWithReachability: network path state nil"}];
            return @"";
        }
        // Note: could fallback on heuristic for iOS <12.0 if nil
        activeInterface = state.defaultActiveInterfaceName;
    } else {
        NSError *err;
        NSSet<NSString*>* upIffList = [NetworkInterface activeInterfaces:&err];
        if (err != nil) {
            NSString *localizedDescription = [NSString stringWithFormat:@"getActiveInterfaceWithReachability: error getting active interfaces %@", err.localizedDescription];
            *outError = [[NSError alloc] initWithDomain:@"iOSLibrary" code:1 userInfo:@{NSLocalizedDescriptionKey: localizedDescription}];
            return @"";
        }
        if (upIffList == nil) {
            *outError = [[NSError alloc] initWithDomain:@"iOSLibrary" code:1 userInfo:@{NSLocalizedDescriptionKey: @"getActiveInterfaceWithReachability: no active interfaces"}];
            return @"";
        }
        activeInterface = [NetworkInterface getActiveInterface:upIffList
                                          currentNetworkStatus:currentNetworkStatus];
    }

    if (activeInterface == nil) {
        *outError = [[NSError alloc] initWithDomain:@"iOSLibrary" code:1 userInfo:@{NSLocalizedDescriptionKey: @"getActiveInterfaceWithReachability: no active interface"}];
        return @"";
    }

    return activeInterface;
}

@end
