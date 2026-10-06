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
#if TARGET_OS_IPHONE
#import <NetworkExtension/NetworkExtension.h>
#endif

@implementation WiFiNetworkInfo {
    WiFiNetworkInfoFetcher fetcher;
    NSTimeInterval timeout;
    void (^logger)(NSString *_Nonnull);

    // Log messages are delivered on their own queue, never while a lock is held or on a thread waiting for a
    // BSSID: delivering a message can block, for example on the provider lock that tunnel-core holds while it
    // requests the network ID.
    dispatch_queue_t logQueue;

    // Guards the state below, and signals when the BSSID is decided, the network changes, or tracking stops.
    NSCondition *condition;
    BOOL started;
    // Incremented whenever a network begins or tracking stops, so that results for earlier networks are ignored.
    uint64_t generation;
    // Whether the current network uses Wi-Fi.
    BOOL usesWiFi;
    // Whether bssid holds the decision for the current network.
    BOOL decided;
    NSString *_Nullable bssid;
    // System uptime at which the current network began and its BSSID fetch started.
    NSTimeInterval networkStart;
    // The network ID kept for the current network, or nil if none is kept yet.
    NSString *_Nullable networkID;
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

- (instancetype)initWithTimeout:(NSTimeInterval)timeout logger:(void (^_Nullable)(NSString *_Nonnull))logger {
    return [self initWithFetcher:[WiFiNetworkInfo defaultFetcher] timeout:timeout logger:logger];
}

- (instancetype)initWithFetcher:(WiFiNetworkInfoFetcher)fetcher
                        timeout:(NSTimeInterval)timeout
                         logger:(void (^_Nullable)(NSString *_Nonnull))logger {
    self = [super init];
    if (self) {
        self->fetcher = [fetcher copy];
        self->timeout = timeout;
        self->logger = [logger copy];
        self->logQueue = dispatch_queue_create("com.psiphon3.library.WiFiNetworkInfoLogQueue", DISPATCH_QUEUE_SERIAL);
        self->condition = [[NSCondition alloc] init];
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

- (void)startUsingWiFi:(BOOL)usesWiFi {
    [self->condition lock];
    if (self->started) {
        [self->condition unlock];
        return;
    }
    self->started = YES;
    uint64_t fetchGeneration = [self beginNetworkUsingWiFiLocked:usesWiFi];
    [self->condition unlock];

    if (usesWiFi) {
        [self fetchForGeneration:fetchGeneration];
    }
}

- (void)stop {
    [self->condition lock];
    self->started = NO;
    self->generation++;
    self->usesWiFi = NO;
    self->decided = YES;
    self->bssid = nil;
    self->networkID = nil;
    [self->condition broadcast];
    [self->condition unlock];
}

- (void)networkChangedUsingWiFi:(BOOL)usesWiFi {
    [self->condition lock];
    if (!self->started) {
        [self->condition unlock];
        return;
    }
    uint64_t fetchGeneration = [self beginNetworkUsingWiFiLocked:usesWiFi];
    [self->condition unlock];

    if (usesWiFi) {
        [self fetchForGeneration:fetchGeneration];
    }
}

- (BOOL)isBSSIDPending {
    [self->condition lock];
    BOOL pending = self->started && self->usesWiFi && !self->decided;
    [self->condition unlock];
    return pending;
}

- (void)waitForBSSID {
    if ([NSThread isMainThread]) {
        return;
    }

    [self->condition lock];
    BOOL timedOut = [self waitForBSSIDLocked];
    [self->condition unlock];

    if (timedOut) {
        [self logTimeout];
    }
}

- (NSString *_Nullable)networkIDWithBuilder:(NS_NOESCAPE WiFiNetworkIDBuilder)builder {
    BOOL timedOut = NO;
    BOOL decidedOnMainThread = NO;

    [self->condition lock];
    if (self->started && self->usesWiFi && self->networkID == nil && !self->decided) {
        if ([NSThread isMainThread]) {
            // The NEHotspotNetwork completion handler runs on the main queue, so the BSSID cannot arrive while
            // this thread waits for it.
            [self decideBSSIDLocked:nil];
            decidedOnMainThread = YES;
        } else {
            timedOut = [self waitForBSSIDLocked];
        }
    }
    // The network may have changed, or tracking stopped, while waiting.
    BOOL available = self->started && self->usesWiFi;
    NSString *keptNetworkID = self->networkID;
    uint64_t buildGeneration = self->generation;
    NSString *buildBSSID = self->bssid;
    [self->condition unlock];

    if (timedOut) {
        [self logTimeout];
    }
    if (decidedOnMainThread) {
        [self log:@"network ID requested on the main thread before the BSSID was fetched; using the fallback "
                  @"network ID for this network"];
    }

    if (!available) {
        return nil;
    }
    if (keptNetworkID != nil) {
        return keptNetworkID;
    }

    // Built without the lock held, as building queries the system.
    BOOL stable = YES;
    NSString *builtNetworkID = builder(buildBSSID, &stable);

    [self->condition lock];
    if (self->started && self->generation == buildGeneration) {
        if (self->networkID != nil) {
            // A concurrent lookup kept its network ID first.
            builtNetworkID = self->networkID;
        } else if (stable) {
            self->networkID = builtNetworkID;
        }
    }
    [self->condition unlock];

    return builtNetworkID;
}

#pragma mark - Private

/// Discards the state of the previous network and returns the generation of the new one. Must be called with the
/// lock held.
- (uint64_t)beginNetworkUsingWiFiLocked:(BOOL)usesWiFi {
    self->generation++;
    self->usesWiFi = usesWiFi;
    // Without Wi-Fi, there is no BSSID to wait for.
    self->decided = !usesWiFi;
    self->bssid = nil;
    self->networkStart = [NSProcessInfo processInfo].systemUptime;
    self->networkID = nil;
    [self->condition broadcast];
    return self->generation;
}

/// Records the BSSID decision for the current network. Must be called with the lock held.
- (void)decideBSSIDLocked:(NSString *_Nullable)decidedBSSID {
    self->bssid = decidedBSSID;
    self->decided = YES;
    [self->condition broadcast];
}

/// Waits until the BSSID of the current network is decided, deciding that there is none once the timeout passes,
/// and returns YES in that case. Must be called with the lock held, and not on the main thread.
- (BOOL)waitForBSSIDLocked {
    while (self->started && self->usesWiFi && !self->decided) {
        // The deadline is shared by all lookups for the network, and does not restart for each one.
        NSTimeInterval remaining = self->networkStart + self->timeout - [NSProcessInfo processInfo].systemUptime;
        if (remaining <= 0) {
            [self decideBSSIDLocked:nil];
            return YES;
        }
        [self->condition waitUntilDate:[NSDate dateWithTimeIntervalSinceNow:remaining]];
    }
    return NO;
}

- (void)logTimeout {
    [self log:[NSString stringWithFormat:@"BSSID not fetched within %.0f ms; using the fallback network ID for this "
                                         @"network",
                                         self->timeout * 1000]];
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
    BOOL current = self->started && fetchGeneration == self->generation;
    BOOL used = current && !self->decided;
    if (used) {
        [self decideBSSIDLocked:accepted];
    }
    [self->condition unlock];

    NSTimeInterval elapsed = [NSProcessInfo processInfo].systemUptime - fetchStart;
    if (used) {
        [self log:[NSString stringWithFormat:@"%@ after %.0f ms",
                   accepted != nil ? @"fetched BSSID" : @"no BSSID available",
                   elapsed * 1000]];
    } else if (current && accepted != nil) {
        [self log:[NSString stringWithFormat:@"fetched BSSID after %.0f ms, after the network ID was chosen without "
                                             @"it; ignoring it until the network changes",
                                             elapsed * 1000]];
    }
}

@end
