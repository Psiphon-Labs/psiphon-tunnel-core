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

#import "DefaultRouteMonitor.h"
#import "NetworkInterface.h"
#import <net/if.h>
#import <ifaddrs.h>
#import <netinet/in.h>
#import <netinet6/in6.h>

@interface NetworkPathState ()
/// See comment in DefaultRouteMonitor.h
@property (nonatomic) NetworkReachability status;
/// See comment in DefaultRouteMonitor.h
@property (nonatomic, nullable) nw_path_t path;
/// See comment in DefaultRouteMonitor.h
@property (nonatomic, nullable) NSString* defaultActiveInterfaceName;
@end

@implementation NetworkPathState

- (instancetype)initWithNetworkReachability:(NetworkReachability)networkReachability
                                       path:(nw_path_t)path
                 defaultActiveInterfaceName:(NSString*)defaultActiveInterfaceName {
    self = [super init];
    if (self) {
        self->_status = networkReachability;
        self->_path = path;
        self->_defaultActiveInterfaceName = defaultActiveInterfaceName;
    }
    return self;
}

@end

@interface ReachabilityChangedNotification ()
/// See comment in DefaultRouteMonitor.h
@property (nonatomic) NetworkReachability reachabilityStatus;
/// See comment in DefaultRouteMonitor.h
@property (nonatomic, nullable) NSString *curDefaultActiveInterfaceName;
/// See comment in DefaultRouteMonitor.h
@property (nonatomic, nullable) NSString *prevDefaultActiveInterfaceName;
@end

@implementation ReachabilityChangedNotification

- (instancetype)initWithReachabilityStatus:(NetworkReachability)networkReachability
             curDefaultActiveInterfaceName:(NSString*)curDefaultActiveInterfaceName
            prevDefaultActiveInterfaceName:(NSString*)prevDefaultActiveInterfaceName {
    self = [super init];
    if (self) {
        self->_reachabilityStatus = networkReachability;
        self->_curDefaultActiveInterfaceName = curDefaultActiveInterfaceName;
        self->_prevDefaultActiveInterfaceName = prevDefaultActiveInterfaceName;
    }
    return self;
}

@end

@interface DefaultRouteMonitor ()
@property (atomic) NetworkPathState *pathState;
@end

@implementation DefaultRouteMonitor {
    nw_path_monitor_t monitor;
    dispatch_queue_t nwPathMonitorQueue;
    dispatch_queue_t notifQueue;

    void (^logger) (NSString *_Nonnull);
}

- (void)initialize API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0)) {
    self.pathState = [[NetworkPathState alloc] initWithNetworkReachability:NetworkReachabilityNotReachable
                                                                      path:nil
                                                defaultActiveInterfaceName:nil];
    self->nwPathMonitorQueue = dispatch_queue_create("com.psiphon3.library.DefaultRouteMonitorNWPathMonitorQueue", DISPATCH_QUEUE_SERIAL);
    self->notifQueue = dispatch_queue_create("com.psiphon3.library.DefaultRouteMonitorNotificationQueue", DISPATCH_QUEUE_SERIAL);
}

- (instancetype)init {
    self = [super init];
    if (self) {
        [self initialize];
    }
    return self;
}

- (instancetype)initWithLogger:(void (^__nonnull)(NSString *_Nonnull))logger {
    self = [super init];
    if (self) {
        self->logger = logger;
        [self initialize];
    }
    return self;
}

- (void)log:(NSString*)notice {
    if (self->logger != nil) {
        self->logger(notice);
    }
}

nw_interface_type_t
nw_path_interface_type(nw_path_t path) API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0)) {
    // Discover active interface type. Follows: https://developer.apple.com/forums/thread/105822?answerId=322343022#322343022.
    if (nw_path_uses_interface_type(path, nw_interface_type_wifi)) {
        return nw_interface_type_wifi;
    } else if (nw_path_uses_interface_type(path, nw_interface_type_cellular)) {
        return nw_interface_type_cellular;
    } else if (nw_path_uses_interface_type(path, nw_interface_type_wired)) {
        return nw_interface_type_wired;
    } else if (nw_path_uses_interface_type(path, nw_interface_type_loopback)) {
        return nw_interface_type_loopback;
    } else {
        return nw_interface_type_other;
    }
}

NetworkReachability nw_interface_type_network_reachability(nw_interface_type_t interface_type) {
    if (interface_type == nw_interface_type_wifi) {
        return NetworkReachabilityReachableViaWiFi;
    } else if (interface_type == nw_interface_type_cellular) {
        return NetworkReachabilityReachableViaCellular;
    } else if (interface_type == nw_interface_type_wired) {
        return NetworkReachabilityReachableViaWired;
    } else if (interface_type == nw_interface_type_loopback) {
        return NetworkReachabilityReachableViaLoopback;
    } else {
        return NetworkReachabilityReachableViaUnknown;
    }
}

- (void)start API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0)) {
    @synchronized (self) {
        // Ensure previous monitor cancelled
        if (self->monitor != nil) {
            nw_path_monitor_cancel(self->monitor);
        }
        self->monitor = nw_path_monitor_create();

        nw_path_monitor_set_queue(self->monitor, self->nwPathMonitorQueue);
        __block dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        nw_path_monitor_set_update_handler(self->monitor, ^(nw_path_t  _Nonnull path) {
            // Do not emit notification on first update. PsiphonTunnel expects that only
            // subsequent path updates will be emitted and will invalidate the DNS cache once the
            // first notification is received.
            BOOL emitNotification = sem == NULL;
            [self pathUpdateHandler:path emitNotification:emitNotification];
            if (sem != NULL) {
                dispatch_semaphore_signal(sem);
                @synchronized (self) {
                    // Release memory after `start` has completed. Otherwise we may set `sem` to
                    // NULL before dispatch_semaphore_wait is called in the enclosing scope and the
                    // program will crash.
                    sem = NULL;
                }
            }
        });
        nw_path_monitor_start(self->monitor);

        // Wait for the current path to be emitted before returning to ensure this instance is
        // populated with the current network state. PsiphonTunnel depends on this guarantee.
        // NOTE: This null guard defends against nw_path_monitor_start calling the update handler
        // synchronously before returning, e.g. with dispatch_sync, which will set `sem` to NULL
        // because @synchronized provides a reentrant thread level locking mechanism.
        if (sem != NULL) {
            dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        }
    }
}

- (void)stop API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0)) {
    @synchronized (self) {
        // Note: this monitor cannot be used after being cancelled. Its update handler will not
        // fire again and cannot be restarted with nw_path_monitor_start. A new monitor must be
        // created and started.
        nw_path_monitor_cancel(self->monitor);
        self->monitor = nil;
    }
}

- (void)pathUpdateHandler:(nw_path_t _Nonnull)path emitNotification:(BOOL)emitNotification API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0)) {

    if (self.pathState.path != nil && pathUpdateIsRedundant(self.pathState.path, path)) {
        // Do nothing, path update is redundant.
        return;
    }

    [self log:[NSString stringWithFormat:@"new path: %@",
               [DefaultRouteMonitor pathDebugInfo:path]]];

    NetworkPathState *newPathState = [[NetworkPathState alloc] init];
    newPathState.path = path;
    NSString *prevDefaultActiveInterfaceName = self.pathState.defaultActiveInterfaceName;

    nw_path_status_t status = nw_path_get_status(path);
    if (status == nw_path_status_invalid || status == nw_path_status_unsatisfied) {
        newPathState.status = NetworkReachabilityNotReachable;
    } else if (status == nw_path_status_satisfied || status == nw_path_status_satisfiable) {

        // Network is, or could, be reachable. Determine interface corresponding to this
        // path.

        nw_interface_type_t active_interface_type = nw_path_interface_type(path);
        newPathState.status = nw_interface_type_network_reachability(active_interface_type);

        NSError *err;
        NSSet<NSString*>* activeInterfaces = [NetworkInterface activeInterfaces:&err];
        if (err != nil) {
            [self log:[NSString stringWithFormat:@"failed to get active interfaces %@", err.localizedDescription]];
            // Continue. activeInterfaces will be an empty set (non-nil) and we still want
            // to log interfaces enumerated with nw_path_enumerate_interfaces for debugging.
        }
        [self log:[NSString stringWithFormat:@"active interfaces %@", [[activeInterfaces allObjects] componentsJoinedByString:@","]]];

        NSMutableArray<NSString*> *candidateInterfaces = [[NSMutableArray alloc] init];
        // Map the active interface type to the interface itself
        nw_path_enumerate_interfaces(path, ^bool(nw_interface_t  _Nonnull interface) {
            nw_interface_type_t interfaceType = nw_interface_get_type(interface);
            [self log:[NSString stringWithFormat:@"enumerated interface %@ with type %d",
                       [NSString stringWithUTF8String:nw_interface_get_name(interface)], interfaceType]];

            if (interfaceType == active_interface_type) {
                NSString *interfaceName = [NSString stringWithUTF8String:nw_interface_get_name(interface)];
                if ([activeInterfaces containsObject:interfaceName]) {
                    [candidateInterfaces addObject:interfaceName];
                    // Note: could return false here to end enumeration and choose first
                    // candidate interface.
                    return true;
                }
            }
            // Continue searching
            return true;
        });
        [self log:[NSString stringWithFormat:@"%lu candidate interfaces",
                   (unsigned long)[candidateInterfaces count]]];

        if ([candidateInterfaces count] > 0) {
            // Arbitrarily choose first interface
            NSString *interfaceName = [candidateInterfaces objectAtIndex:0];
            newPathState.defaultActiveInterfaceName = interfaceName;
            [self log:[NSString stringWithFormat:@"active interface %@", interfaceName]];
        } else {
            // This should never happen
        }
    } else {
        // Unhandled case. Should never happen.
    }
    self.pathState = newPathState;

    if (emitNotification == TRUE) {
        // Backwards compatibility with Reachability
        ReachabilityChangedNotification *notif =
            [[ReachabilityChangedNotification alloc]
             initWithReachabilityStatus:self.pathState.status
             curDefaultActiveInterfaceName:newPathState.defaultActiveInterfaceName
             prevDefaultActiveInterfaceName:prevDefaultActiveInterfaceName];
        dispatch_async(self->notifQueue, ^{
            [[NSNotificationCenter defaultCenter]
             postNotificationName:[DefaultRouteMonitor reachabilityChangedNotification]
             object:notif];
        });
    }
}

/// Returns true if the network state represented by newPath is considered equivalent, for our purposes, to that represented by oldPath;
/// otherwise returns false.
bool pathUpdateIsRedundant(nw_path_t oldPath, nw_path_t newPath) API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0)) {

    // Note: nw_path_is_equal may return FALSE even though the paths are identical when comparing
    // all the information that can be gathered with the public nw_path APIs.
    if (nw_path_is_equal(oldPath, newPath)) {
        return TRUE;
    }

    nw_interface_type_t interfaceType = nw_path_interface_type(oldPath);
    if (interfaceType != nw_path_interface_type(newPath)) {
        return FALSE;
    }

    if (nw_path_get_status(oldPath) != nw_path_get_status(newPath)) {
        return FALSE;
    }

    // Compare path interfaces that match the active interface type

    NSArray<nw_interface_t>* pathInterfaces = [DefaultRouteMonitor pathInterfaces:oldPath withType:interfaceType];
    NSArray<nw_interface_t>* otherPathInterfaces = [DefaultRouteMonitor pathInterfaces:newPath withType:interfaceType];
    if ([pathInterfaces count] != [otherPathInterfaces count]) {
        return FALSE;
    }

    // Note: we do not compare the values returned by other public nw_path_* APIs because testing
    // has shown us these values can change when the active interface has not and we want to reduce
    // the chance of false negatives.

    return TRUE;
}

+ (NSString*)pathDebugInfo:(nw_path_t)path API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0)) {

    if (path == nil) {
        return @"state nil";
    }

    NSString *constrained = @"UNAVAILABLE";
    if (@available(iOS 13.0, *)) {
        constrained = [NSString stringWithFormat:@"%d", nw_path_is_constrained(path)];
    }

    NSString *unsatisfiedReason = @"UNAVAILABLE";
    if (@available(iOS 14.2, *)) {
        nw_path_unsatisfied_reason_t reason = nw_path_get_unsatisfied_reason(path);
        if (reason == nw_path_unsatisfied_reason_wifi_denied) {
            unsatisfiedReason = @"WIFI_DENIED";
        } else if (reason == nw_path_unsatisfied_reason_cellular_denied) {
            unsatisfiedReason = @"CELLULAR_DENIED";
        } else if (reason == nw_path_unsatisfied_reason_local_network_denied) {
            unsatisfiedReason = @"LOCAL_NETWORK_DENIED";
        } else if (reason == nw_path_unsatisfied_reason_not_available) {
            unsatisfiedReason = @"NOT_AVAILABLE";
        } else {
            unsatisfiedReason = @"UNKNOWN";
        }
    }

    NSString *s = [NSString stringWithFormat:
                   @"status %@, "
                   "active_interface_type %@, "
                   "path_is_expensive %d, "
                   "path_is_constrained %@, "
                   "path_has_ipv4 %d, "
                   "path_has_ipv6 %d, "
                   "path_has_dns %d, "
                   "unsatisfied_reason %@",
                   [DefaultRouteMonitor pathStatusToString:nw_path_get_status(path)],
                   [DefaultRouteMonitor interfaceTypeToString:nw_path_interface_type(path)],
                   nw_path_is_expensive(path), constrained, nw_path_has_ipv4(path),
                   nw_path_has_ipv6(path), nw_path_has_dns(path), unsatisfiedReason];
    return s;
}

#pragma mark ReachabilityProtocol

+ (NSString*)reachabilityChangedNotification {
    return @"kNetworkReachabilityChangedNotification";
}

- (BOOL)startNotifier {
    [self log:@"starting NWPathMonitor"];
    [self start];
    return TRUE;
}

- (void)stopNotifier {
    [self log:@"stopping NWPathMonitor"];
    [self stop];
}

- (NetworkReachability)reachabilityStatus {
    // Note: alternatively we could initialize a temporary NWPathMonitor instance and sample the
    // reachability state by synchronously waiting for its initial update.
    return self.pathState.status;
}

- (NSString*)reachabilityStatusDebugInfo {
    return [DefaultRouteMonitor pathDebugInfo:self.pathState.path];
}

#pragma mark Helpers (private)

+ (NSString*)interfaceTypeToString:(nw_interface_type_t)type {
    if (type == nw_interface_type_wifi) {
        return @"WIFI";
    } else if (type == nw_interface_type_cellular) {
        return @"CELLULAR";
    } else if (type == nw_interface_type_wired) {
        return @"WIRED";
    } else if (type == nw_interface_type_loopback) {
        return @"LOOPBACK";
    } else if (type == nw_interface_type_other) {
        return @"OTHER";
    } else {
        return @"UNKNOWN";
    }
}

+ (NSString*)pathStatusToString:(nw_path_status_t)status {
    if (status == nw_path_status_satisfied) {
        return @"SATISFIED";
    } else if (status == nw_path_status_satisfiable) {
        return @"SATISFIABLE";
    } else if (status == nw_path_status_unsatisfied) {
        return @"UNSATISFIED";
    } else if (status == nw_path_status_invalid) {
        return @"INVALID";
    } else {
        return @"UNKNOWN";
    }
}

+ (NSArray<nw_interface_t>*)pathInterfaces:(nw_path_t)path withType:(nw_interface_type_t)interfaceType API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0)) {
    NSMutableArray<nw_interface_t>* interfaces = [[NSMutableArray alloc] init];

    nw_path_enumerate_interfaces(path, ^bool(nw_interface_t  _Nonnull interface) {
        if (nw_interface_get_type(interface) == interfaceType) {
            [interfaces addObject:interface];
        }
        return TRUE;
    });

    return interfaces;
}

bool interfaceIsEqual(nw_interface_t interface, nw_interface_t otherInterface) API_AVAILABLE(macos(10.14), ios(12.0), watchos(5.0), tvos(12.0)) {
    if (nw_interface_get_index(interface) != nw_interface_get_index(otherInterface) ||
        strcmp(nw_interface_get_name(interface), nw_interface_get_name(otherInterface)) != 0 ||
        nw_interface_get_type(interface) != nw_interface_get_type(otherInterface)) {
        return FALSE;
    }
    return TRUE;
}

@end
