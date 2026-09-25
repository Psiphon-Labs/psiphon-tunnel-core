/*
 * Copyright (c) 2026, Psiphon Inc.
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

#import "WiFiNetworkInfo.h"
#import <Network/Network.h>
#if TARGET_OS_IPHONE
#import <NetworkExtension/NetworkExtension.h>
#endif

@implementation WiFiNetworkInfo {
    WiFiNetworkInfoFetcher fetcher;
    BOOL monitorsPath;
    void (^logger)(NSString *_Nonnull);

    // Log messages are delivered on their own queue, never while a lock is held or on a thread waiting for a
    // BSSID: delivering a message can block, for example on the provider lock that tunnel-core holds while it
    // requests the network ID.
    dispatch_queue_t logQueue;
    dispatch_queue_t pathMonitorQueue;

    // Guards the state below, and signals when a result is stored or invalidated.
    NSCondition *condition;
    BOOL started;
    // Incremented whenever the cached BSSID is discarded, so that late results of earlier fetches are ignored.
    uint64_t generation;
    // Whether bssid holds the result for the current generation.
    BOOL resolved;
    NSString *_Nullable bssid;
    // Whether a lookup gave up waiting for the result of the current generation.
    BOOL waitTimedOut;
    nw_path_monitor_t _Nullable pathMonitor;
}

+ (WiFiNetworkInfoFetcher)defaultFetcher {
    return ^(WiFiNetworkInfoFetchCompletion completion) {
#if TARGET_OS_IPHONE
        if (@available(iOS 14.0, macCatalyst 14.0, *)) {
            [NEHotspotNetwork fetchCurrentWithCompletionHandler:^(NEHotspotNetwork *_Nullable currentNetwork) {
                completion(currentNetwork.BSSID);
            }];
            return;
        }
#endif
        completion(nil);
    };
}

+ (NSString *_Nullable)acceptedBSSID:(NSString *_Nullable)bssid {
    if (bssid.length == 0) {
        return nil;
    }

    // Normalize letter case and leading zeros for the comparison only.
    NSMutableArray<NSString *> *octets = [NSMutableArray array];
    for (NSString *octet in [bssid.lowercaseString componentsSeparatedByString:@":"]) {
        [octets addObject:octet.length == 1 ? [@"0" stringByAppendingString:octet] : octet];
    }
    NSString *normalized = [octets componentsJoinedByString:@":"];
    if ([normalized isEqualToString:@"00:00:00:00:00:00"] || [normalized isEqualToString:@"02:00:00:00:00:00"]) {
        return nil;
    }

    return bssid;
}

- (instancetype)initWithLogger:(void (^_Nullable)(NSString *_Nonnull))logger {
    return [self initWithFetcher:[WiFiNetworkInfo defaultFetcher] monitorsPath:YES logger:logger];
}

- (instancetype)initWithFetcher:(WiFiNetworkInfoFetcher)fetcher
                   monitorsPath:(BOOL)monitorsPath
                         logger:(void (^_Nullable)(NSString *_Nonnull))logger {
    self = [super init];
    if (self) {
        self->fetcher = [fetcher copy];
        self->monitorsPath = monitorsPath;
        self->logger = [logger copy];
        self->logQueue = dispatch_queue_create("com.psiphon3.library.WiFiNetworkInfoLogQueue", DISPATCH_QUEUE_SERIAL);
        self->pathMonitorQueue = dispatch_queue_create("com.psiphon3.library.WiFiNetworkInfoPathMonitorQueue", DISPATCH_QUEUE_SERIAL);
        self->condition = [[NSCondition alloc] init];
        // Until started, lookups return nil without waiting.
        self->resolved = YES;
    }
    return self;
}

- (void)log:(NSString *)message {
    void (^logger)(NSString *_Nonnull) = self->logger;
    if (logger == nil) {
        return;
    }
    dispatch_async(self->logQueue, ^{
        logger([@"WiFiNetworkInfo: " stringByAppendingString:message]);
    });
}

- (void)start {
    [self->condition lock];
    if (self->started) {
        [self->condition unlock];
        return;
    }
    self->started = YES;
    [self invalidateLocked];
    [self->condition unlock];

    if (!self->monitorsPath) {
        return;
    }

    if (@available(iOS 12.0, macOS 10.14, *)) {
        nw_path_monitor_t monitor = nw_path_monitor_create();
        nw_path_monitor_set_queue(monitor, self->pathMonitorQueue);
        __weak WiFiNetworkInfo *weakSelf = self;
        nw_path_monitor_set_update_handler(monitor, ^(nw_path_t _Nonnull path) {
            nw_path_status_t status = nw_path_get_status(path);
            BOOL usable = status == nw_path_status_satisfied || status == nw_path_status_satisfiable;
            [weakSelf pathUpdatedUsingWiFi:usable && nw_path_uses_interface_type(path, nw_interface_type_wifi)];
        });

        [self->condition lock];
        if (!self->started) {
            // Stopped concurrently.
            [self->condition unlock];
            return;
        }
        self->pathMonitor = monitor;
        [self->condition unlock];

        // The first update is delivered promptly with the current path.
        nw_path_monitor_start(monitor);
    } else {
        // Without path updates the BSSID would stay pending, so record that there is none.
        [self->condition lock];
        [self storeResultLocked:nil];
        [self->condition unlock];
    }
}

- (void)stop {
    [self->condition lock];
    self->started = NO;
    self->generation++;
    self->waitTimedOut = NO;
    [self storeResultLocked:nil];
    nw_path_monitor_t monitor = self->pathMonitor;
    self->pathMonitor = nil;
    [self->condition unlock];

    if (monitor != nil) {
        if (@available(iOS 12.0, macOS 10.14, *)) {
            nw_path_monitor_cancel(monitor);
        }
    }
}

- (void)invalidateAndRefetch {
    [self->condition lock];
    if (!self->started) {
        [self->condition unlock];
        return;
    }
    uint64_t fetchGeneration = [self invalidateLocked];
    [self->condition unlock];

    [self fetchForGeneration:fetchGeneration];
}

- (void)pathUpdatedUsingWiFi:(BOOL)usesWiFi {
    [self->condition lock];
    if (!self->started) {
        [self->condition unlock];
        return;
    }
    uint64_t fetchGeneration = [self invalidateLocked];
    if (!usesWiFi) {
        [self storeResultLocked:nil];
    }
    [self->condition unlock];

    if (usesWiFi) {
        [self fetchForGeneration:fetchGeneration];
    }
}

- (NSString *_Nullable)bssidWaitingUpTo:(NSTimeInterval)timeout {
    // The NEHotspotNetwork completion handler runs on the main queue, so waiting on the main thread would only
    // delay the result it is waiting for.
    BOOL mayWait = ![NSThread isMainThread];
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
    BOOL timedOut = NO;

    [self->condition lock];
    while (mayWait && !self->resolved && !self->waitTimedOut) {
        if (![self->condition waitUntilDate:deadline] && !self->resolved) {
            self->waitTimedOut = YES;
            timedOut = YES;
        }
    }
    NSString *result = self->resolved ? self->bssid : nil;
    [self->condition unlock];

    if (timedOut) {
        [self log:[NSString stringWithFormat:@"timed out after %.0f ms waiting for the BSSID", timeout * 1000]];
    }
    return result;
}

#pragma mark - Private

/// Discards the cached BSSID and returns the new generation. Must be called with the lock held.
- (uint64_t)invalidateLocked {
    self->generation++;
    self->resolved = NO;
    self->bssid = nil;
    self->waitTimedOut = NO;
    [self->condition broadcast];
    return self->generation;
}

/// Stores the result for the current generation. Must be called with the lock held.
- (void)storeResultLocked:(NSString *_Nullable)result {
    self->bssid = result;
    self->resolved = YES;
    [self->condition broadcast];
}

- (void)fetchForGeneration:(uint64_t)fetchGeneration {
    NSTimeInterval fetchStart = [NSProcessInfo processInfo].systemUptime;
    __weak WiFiNetworkInfo *weakSelf = self;
    // Called without the lock held, as the fetcher may complete synchronously.
    self->fetcher(^(NSString *_Nullable fetchedBSSID) {
        [weakSelf completeFetchForGeneration:fetchGeneration bssid:fetchedBSSID fetchStart:fetchStart];
    });
}

- (void)completeFetchForGeneration:(uint64_t)fetchGeneration
                             bssid:(NSString *_Nullable)fetchedBSSID
                        fetchStart:(NSTimeInterval)fetchStart {
    NSString *accepted = [WiFiNetworkInfo acceptedBSSID:fetchedBSSID];

    [self->condition lock];
    BOOL current = self->started && fetchGeneration == self->generation && !self->resolved;
    if (current) {
        [self storeResultLocked:accepted];
    }
    [self->condition unlock];

    if (current) {
        NSTimeInterval elapsed = [NSProcessInfo processInfo].systemUptime - fetchStart;
        [self log:[NSString stringWithFormat:@"%@ after %.0f ms",
                   accepted != nil ? @"fetched BSSID" : @"no BSSID available",
                   elapsed * 1000]];
    }
}

@end
