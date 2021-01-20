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
#import <Network/path.h>
#import <Network/path_monitor.h>

@implementation NetworkPathState

@end

@implementation NetworkInterface

+ (NSSet<NSString*>*)activeInterfaces {

    NSMutableSet *upIffList = [NSMutableSet new];

    struct ifaddrs *interfaces;
    if (getifaddrs(&interfaces) != 0) {
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

+ (NetworkPathState*)networkPathState:(NSSet<NSString*>*)activeInterfaces {

    __block NetworkPathState *state = [[NetworkPathState alloc] init];

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    nw_path_monitor_t monitor = nw_path_monitor_create();

    nw_path_monitor_set_update_handler(monitor, ^(nw_path_t  _Nonnull path) {

        // Discover the active interface type

        nw_interface_type_t active_interface_type = nw_interface_type_other;

        if (nw_path_uses_interface_type(path, nw_interface_type_wifi)) {
            active_interface_type = nw_interface_type_wifi;
        } else if (nw_path_uses_interface_type(path, nw_interface_type_cellular)) {
            active_interface_type = nw_interface_type_cellular;
        } else if (nw_path_uses_interface_type(path, nw_interface_type_wired)) {
            active_interface_type = nw_interface_type_wired;
        } else if (nw_path_uses_interface_type(path, nw_interface_type_loopback)) {
            active_interface_type = nw_interface_type_loopback;
        } else {
            active_interface_type = nw_interface_type_other;
        }

        // Map the active interface type to the interface itself
        nw_path_enumerate_interfaces(path, ^bool(nw_interface_t  _Nonnull interface) {

            if (nw_interface_get_type(interface) == active_interface_type) {
                NSString *interfaceName = [NSString stringWithUTF8String:nw_interface_get_name(interface)];
                if (state.defaultActiveInterface == NULL && (activeInterfaces == nil || [activeInterfaces containsObject:interfaceName])) {
                    state.defaultActiveInterface = interface;
                    return false;
                }
            }

            // Continue searching
            return true;
        });

        dispatch_semaphore_signal(sem);
    });

    nw_path_monitor_set_queue(monitor, dispatch_queue_create("com.psiphon3.library.NWInterfaceNWPathMonitorQueue", DISPATCH_QUEUE_SERIAL));
    nw_path_monitor_start(monitor);

    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

    return state;
}

@end
