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

#import <XCTest/XCTest.h>

#import <arpa/inet.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <net/if_dl.h>
#import <netdb.h>

#import "DefaultRouteMonitor.h"
#import "NetworkID.h"
#import "NetworkInterface.h"
#import "PsiphonTunnel.h"
#import "WiFiNetworkInfo.h"

@interface PsiphonTunnel (CallbackTesting)
- (void)onAccessToken:(NSString *)token;
- (void)handlePsiphonNotice:(NSString *)noticeJSON;
@end

@interface PsiphonTunnelDelegate : NSObject <TunneledAppDelegate>
@property (nonatomic, copy) NSString *diagnosticMessage;
@end
@implementation PsiphonTunnelDelegate

- (NSString * _Nullable)getPsiphonConfig {
    return @"";
}

- (void)onDiagnosticMessage:(NSString *)message withTimestamp:(NSString *)timestamp {
    self.diagnosticMessage = message;
}

@end

@interface PsiphonAccessTokenDelegate : PsiphonTunnelDelegate
@property (nonatomic, copy) NSString *accessToken;
@property (nonatomic) NSUInteger accessTokenCallbacks;
@property (nonatomic, copy) void (^accessTokenHandler)(NSString *token);
@end

@implementation PsiphonAccessTokenDelegate

- (void)onAccessToken:(NSString *)token {
    self.accessToken = token;
    self.accessTokenCallbacks++;
    if (self.accessTokenHandler != nil) {
        self.accessTokenHandler(token);
    }
}

@end


@interface PsiphonTunnelTests : XCTestCase
@property PsiphonTunnelDelegate *psiphonTunnelDelegate;
@end

@implementation PsiphonTunnelTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    self.psiphonTunnelDelegate = [[PsiphonTunnelDelegate alloc] init];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testExample {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
    
    PsiphonTunnel *tunnel = [PsiphonTunnel newPsiphonTunnel:self.psiphonTunnelDelegate];
    XCTAssertNotNil(tunnel);
}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

- (void)testAccessTokenCallback {
    PsiphonAccessTokenDelegate *delegate = [[PsiphonAccessTokenDelegate alloc] init];
    PsiphonTunnel *tunnel = [PsiphonTunnel newPsiphonTunnel:delegate];
    delegate.diagnosticMessage = nil;
    XCTestExpectation *received = [self expectationWithDescription:@"access token received"];
    delegate.accessTokenHandler = ^(NSString *token) {
        [received fulfill];
    };

    [tunnel onAccessToken:@"-_8AgAE"];
    [self waitForExpectations:@[received] timeout:5];

    XCTAssertEqualObjects(delegate.accessToken, @"-_8AgAE");
    XCTAssertEqual(delegate.accessTokenCallbacks, 1U);
    XCTAssertNil(delegate.diagnosticMessage);

    [tunnel handlePsiphonNotice:@"{\"noticeType\":\"DSLAccessTokenAvailable\",\"data\":{},\"timestamp\":\"2026-01-01T00:00:00Z\"}"];

    XCTAssertEqualObjects(delegate.diagnosticMessage, @"DSLAccessTokenAvailable: {}");
    XCTAssertEqual(delegate.accessTokenCallbacks, 1U);
}

- (void)testAccessTokenWithoutCallback {
    PsiphonTunnel *tunnel = [PsiphonTunnel newPsiphonTunnel:self.psiphonTunnelDelegate];
    self.psiphonTunnelDelegate.diagnosticMessage = nil;

    [tunnel onAccessToken:@"-_8AgAE"];

    XCTAssertNil(self.psiphonTunnelDelegate.diagnosticMessage);
}

- (void)testAccessTokenCallbacksAreAsynchronousAndOrdered {
    PsiphonAccessTokenDelegate *delegate = [[PsiphonAccessTokenDelegate alloc] init];
    PsiphonTunnel *tunnel = [PsiphonTunnel newPsiphonTunnel:delegate];
    XCTestExpectation *entered = [self expectationWithDescription:@"first callback entered"];
    XCTestExpectation *returned = [self expectationWithDescription:@"provider calls returned"];
    XCTestExpectation *received = [self expectationWithDescription:@"both tokens received"];
    received.expectedFulfillmentCount = 2;
    dispatch_semaphore_t releaseCallback = dispatch_semaphore_create(0);
    NSMutableArray<NSString *> *tokens = [NSMutableArray array];

    delegate.accessTokenHandler = ^(NSString *token) {
        if ([token isEqualToString:@"first"]) {
            [entered fulfill];
            dispatch_semaphore_wait(releaseCallback, DISPATCH_TIME_FOREVER);
        }
        [tokens addObject:token];
        [received fulfill];
    };

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        [tunnel onAccessToken:@"first"];
        [tunnel onAccessToken:@"second"];
        [returned fulfill];
    });

    // Both provider calls must return while the first application callback is blocked.
    [self waitForExpectations:@[entered, returned] timeout:5];
    dispatch_semaphore_signal(releaseCallback);
    [self waitForExpectations:@[received] timeout:5];
    XCTAssertEqualObjects(tokens, (@[@"first", @"second"]));
}

@end


/// FakeInterfaceAddresses builds a getifaddrs(3) style list for exercising NetworkInterfaceSelectAddress.
@interface FakeInterfaceAddresses : NSObject
@property (nonatomic, readonly, nullable) const struct ifaddrs *list;
@end

@implementation FakeInterfaceAddresses {
    NSMutableArray<NSMutableData *> *_buffers;
    struct ifaddrs *_last;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _buffers = [NSMutableArray array];
    }
    return self;
}

/// Appends an entry for an up interface. address is an IPv4 or IPv6 literal.
- (void)addInterface:(const char *)name address:(const char *)address {
    [self addInterface:name address:address flags:IFF_UP];
}

/// Appends an entry. address is an IPv4 or IPv6 literal, or NULL for an entry with no address.
- (void)addInterface:(const char *)name address:(const char *)address flags:(unsigned int)flags {
    struct sockaddr *addr = NULL;
    if (address != NULL) {
        addr = [self newSockaddr];
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        if (inet_pton(AF_INET, address, &addr4->sin_addr) == 1) {
            addr4->sin_len = sizeof(*addr4);
            addr4->sin_family = AF_INET;
        } else if (inet_pton(AF_INET6, address, &addr6->sin6_addr) == 1) {
            addr6->sin6_len = sizeof(*addr6);
            addr6->sin6_family = AF_INET6;
        } else {
            [NSException raise:NSInvalidArgumentException format:@"invalid address %s", address];
        }
    }
    [self appendName:name addr:addr flags:flags];
}

/// Appends a link-layer entry for an up interface, as getifaddrs(3) returns for every interface.
- (void)addLinkLayerInterface:(const char *)name {
    struct sockaddr *addr = [self newSockaddr];
    addr->sa_len = sizeof(struct sockaddr_dl);
    addr->sa_family = AF_LINK;
    [self appendName:name addr:addr flags:IFF_UP];
}

- (struct sockaddr *)newSockaddr {
    NSMutableData *buffer = [NSMutableData dataWithLength:sizeof(struct sockaddr_storage)];
    [_buffers addObject:buffer];
    return buffer.mutableBytes;
}

- (void)appendName:(const char *)name addr:(struct sockaddr *)addr flags:(unsigned int)flags {
    NSMutableData *buffer = [NSMutableData dataWithLength:sizeof(struct ifaddrs)];
    [_buffers addObject:buffer];
    struct ifaddrs *entry = buffer.mutableBytes;
    entry->ifa_name = (char *)name;
    entry->ifa_flags = flags;
    entry->ifa_addr = addr;

    if (_last == NULL) {
        _list = entry;
    } else {
        _last->ifa_next = entry;
    }
    _last = entry;
}

@end

/// Returns the address NetworkInterfaceSelectAddress selects for en0, or nil if none is selected.
static NSString *_Nullable SelectedAddress(FakeInterfaceAddresses *interfaces, BOOL preferIPv4) {
    const struct ifaddrs *selected = NetworkInterfaceSelectAddress(interfaces.list, "en0", preferIPv4);
    if (selected == NULL) {
        return nil;
    }
    const struct sockaddr *addr = selected->ifa_addr;
    const void *src = addr->sa_family == AF_INET ?
        (const void *)&((const struct sockaddr_in *)addr)->sin_addr :
        (const void *)&((const struct sockaddr_in6 *)addr)->sin6_addr;
    char buffer[INET6_ADDRSTRLEN];
    if (inet_ntop(addr->sa_family, src, buffer, sizeof(buffer)) == NULL) {
        return nil;
    }
    return @(buffer);
}

@interface NetworkInterfaceTests : XCTestCase
@end

@implementation NetworkInterfaceTests

- (void)testPreferIPv4SelectsIPv4RegardlessOfOrder {
    FakeInterfaceAddresses *ipv6First = [[FakeInterfaceAddresses alloc] init];
    [ipv6First addLinkLayerInterface:"en0"];
    [ipv6First addInterface:"en0" address:"fe80::1"];
    [ipv6First addInterface:"en0" address:"2001:db8::1"];
    [ipv6First addInterface:"en0" address:"2001:db8::2"];
    [ipv6First addInterface:"en0" address:"192.0.2.1"];
    XCTAssertEqualObjects(SelectedAddress(ipv6First, YES), @"192.0.2.1");

    FakeInterfaceAddresses *ipv4First = [[FakeInterfaceAddresses alloc] init];
    [ipv4First addInterface:"en0" address:"192.0.2.1"];
    [ipv4First addInterface:"en0" address:"2001:db8::1"];
    XCTAssertEqualObjects(SelectedAddress(ipv4First, YES), @"192.0.2.1");

    FakeInterfaceAddresses *twoIPv4 = [[FakeInterfaceAddresses alloc] init];
    [twoIPv4 addInterface:"en0" address:"2001:db8::1"];
    [twoIPv4 addInterface:"en0" address:"192.0.2.1"];
    [twoIPv4 addInterface:"en0" address:"192.0.2.2"];
    XCTAssertEqualObjects(SelectedAddress(twoIPv4, YES), @"192.0.2.1");
}

- (void)testPreferIPv4SkipsLinkLocal {
    FakeInterfaceAddresses *withIPv4 = [[FakeInterfaceAddresses alloc] init];
    [withIPv4 addInterface:"en0" address:"fe80::1"];
    [withIPv4 addInterface:"en0" address:"169.254.1.1"];
    [withIPv4 addInterface:"en0" address:"192.0.2.1"];
    XCTAssertEqualObjects(SelectedAddress(withIPv4, YES), @"192.0.2.1");

    // A self-assigned IPv4 address alongside a global IPv6 address, as on an IPv6-only network.
    FakeInterfaceAddresses *ipv6Only = [[FakeInterfaceAddresses alloc] init];
    [ipv6Only addInterface:"en0" address:"169.254.1.1"];
    [ipv6Only addInterface:"en0" address:"fe80::1"];
    [ipv6Only addInterface:"en0" address:"2001:db8::1"];
    XCTAssertEqualObjects(SelectedAddress(ipv6Only, YES), @"2001:db8::1");

    FakeInterfaceAddresses *linkLocalOnly = [[FakeInterfaceAddresses alloc] init];
    [linkLocalOnly addInterface:"en0" address:"169.254.1.1"];
    [linkLocalOnly addInterface:"en0" address:"fe80::1"];
    XCTAssertNil(SelectedAddress(linkLocalOnly, YES));
}

- (void)testPreferIPv4SelectsFirstIPv6WithoutIPv4 {
    FakeInterfaceAddresses *interfaces = [[FakeInterfaceAddresses alloc] init];
    [interfaces addLinkLayerInterface:"en0"];
    [interfaces addInterface:"en0" address:"fe80::1"];
    [interfaces addInterface:"en0" address:"2001:db8::1"];
    [interfaces addInterface:"en0" address:"2001:db8::2"];
    XCTAssertEqualObjects(SelectedAddress(interfaces, YES), @"2001:db8::1");
}

// Without preferIPv4, the selection is unchanged for the cellular, wired and macOS network IDs.
- (void)testWithoutPreferIPv4SelectsFirstAddress {
    FakeInterfaceAddresses *ipv6First = [[FakeInterfaceAddresses alloc] init];
    [ipv6First addLinkLayerInterface:"en0"];
    [ipv6First addInterface:"en0" address:"fe80::1"];
    [ipv6First addInterface:"en0" address:"2001:db8::1"];
    [ipv6First addInterface:"en0" address:"192.0.2.1"];
    XCTAssertEqualObjects(SelectedAddress(ipv6First, NO), @"2001:db8::1");

    FakeInterfaceAddresses *linkLocalIPv4First = [[FakeInterfaceAddresses alloc] init];
    [linkLocalIPv4First addInterface:"en0" address:"169.254.1.1"];
    [linkLocalIPv4First addInterface:"en0" address:"192.0.2.1"];
    XCTAssertEqualObjects(SelectedAddress(linkLocalIPv4First, NO), @"169.254.1.1");

    FakeInterfaceAddresses *linkLocalIPv6Only = [[FakeInterfaceAddresses alloc] init];
    [linkLocalIPv6Only addInterface:"en0" address:"fe80::1"];
    XCTAssertNil(SelectedAddress(linkLocalIPv6Only, NO));
}

- (void)testSelectsOnlyUpNonLoopbackEntriesOfNamedInterface {
    FakeInterfaceAddresses *interfaces = [[FakeInterfaceAddresses alloc] init];
    [interfaces addInterface:"en1" address:"192.0.2.1"];
    [interfaces addInterface:"en0" address:"192.0.2.2" flags:0];
    [interfaces addInterface:"en0" address:"192.0.2.3" flags:IFF_UP | IFF_LOOPBACK];
    [interfaces addInterface:NULL address:"192.0.2.4" flags:IFF_UP];
    [interfaces addInterface:"en0" address:NULL flags:IFF_UP];
    [interfaces addLinkLayerInterface:"en0"];
    [interfaces addInterface:"en00" address:"192.0.2.5"];
    [interfaces addInterface:"en0" address:"2001:db8::1"];
    XCTAssertEqualObjects(SelectedAddress(interfaces, YES), @"2001:db8::1");
    XCTAssertEqualObjects(SelectedAddress(interfaces, NO), @"2001:db8::1");

    XCTAssertTrue(NetworkInterfaceSelectAddress(interfaces.list, NULL, YES) == NULL);
    XCTAssertTrue(NetworkInterfaceSelectAddress(NULL, "en0", YES) == NULL);
    XCTAssertTrue(NetworkInterfaceSelectAddress(NULL, "en0", NO) == NULL);
}

// getInterfaceAddress formats the address selected from the live interface list.
- (void)testGetInterfaceAddressFormatsSelectedAddress {
    NSError *err;
    NSSet<NSString *> *activeInterfaces = [NetworkInterface activeInterfaces:&err];
    XCTAssertNil(err);

    for (NSString *interfaceName in activeInterfaces) {
        for (NSNumber *preferIPv4 in @[@YES, @NO]) {
            struct ifaddrs *interfaces;
            if (getifaddrs(&interfaces) != 0) {
                XCTFail(@"getifaddrs error with errno %d", errno);
                return;
            }
            const struct ifaddrs *selected = NetworkInterfaceSelectAddress(interfaces,
                                                                           interfaceName.UTF8String,
                                                                           preferIPv4.boolValue);
            NSString *expected = nil;
            if (selected != NULL) {
                char buffer[NI_MAXHOST];
                XCTAssertEqual(getnameinfo(selected->ifa_addr, selected->ifa_addr->sa_len,
                                           buffer, sizeof(buffer), NULL, 0, NI_NUMERICHOST), 0);
                expected = @(buffer);
            }
            freeifaddrs(interfaces);

            NSString *address = [NetworkInterface getInterfaceAddress:interfaceName
                                                           preferIPv4:preferIPv4.boolValue
                                                                error:&err];
            XCTAssertNil(err);
            XCTAssertEqualObjects(address, expected, @"%@ preferIPv4 %@", interfaceName, preferIPv4);
        }
    }

    XCTAssertNil([NetworkInterface getInterfaceAddress:@"lo0" preferIPv4:YES error:&err]);
    XCTAssertNil(err);
}

@end


@interface NetworkIDTests : XCTestCase
@end

@implementation NetworkIDTests

static NetworkIDCurrentNetworkInfoBSSIDs CurrentNetworkInfoBSSIDs(NSArray<NSString *> *bssids, BOOL *called) {
    return ^NSArray<NSString *> *{
        *called = YES;
        return bssids;
    };
}

static NetworkIDInterfaceAddress InterfaceAddress(NSString *_Nullable address, BOOL *called) {
    return ^NSString *(NSError *_Nullable *_Nonnull outError) {
        *called = YES;
        if (address == nil) {
            *outError = [NSError errorWithDomain:@"test" code:1 userInfo:@{NSLocalizedDescriptionKey: @"no address"}];
            return @"";
        }
        return address;
    };
}

- (void)testWiFiNetworkIDPrefersHotspotBSSID {
    BOOL currentNetworkInfoCalled = NO, addressCalled = NO;
    NSError *warn;
    NSString *networkID = [NetworkID wifiNetworkIDWithBSSID:@"e4:38:83:e6:c0:b1"
                                   currentNetworkInfoBSSIDs:CurrentNetworkInfoBSSIDs(@[@"0:1a:2b:3c:4d:5e"], &currentNetworkInfoCalled)
                                           interfaceAddress:InterfaceAddress(@"192.0.2.1", &addressCalled)
                                                    warning:&warn];
    XCTAssertEqualObjects(networkID, @"WIFI-e4:38:83:e6:c0:b1");
    XCTAssertNil(warn);
    XCTAssertFalse(currentNetworkInfoCalled, @"deprecated API queried although NEHotspotNetwork returned a BSSID");
    XCTAssertFalse(addressCalled);
}

- (void)testWiFiNetworkIDFallsBackToCurrentNetworkInfoBSSIDs {
    for (NSString *hotspotBSSID in @[[NSNull null], @""]) {
        BOOL currentNetworkInfoCalled = NO, addressCalled = NO;
        NSError *warn;
        NSString *networkID = [NetworkID wifiNetworkIDWithBSSID:[hotspotBSSID isKindOfClass:[NSString class]] ? (NSString *)hotspotBSSID : nil
                                       currentNetworkInfoBSSIDs:CurrentNetworkInfoBSSIDs(@[@"0:1a:2b:3c:4d:5e"], &currentNetworkInfoCalled)
                                               interfaceAddress:InterfaceAddress(@"192.0.2.1", &addressCalled)
                                                        warning:&warn];
        XCTAssertEqualObjects(networkID, @"WIFI-0:1a:2b:3c:4d:5e");
        XCTAssertNil(warn);
        XCTAssertTrue(currentNetworkInfoCalled);
        XCTAssertFalse(addressCalled);
    }

    // As before, one suffix per interface that reports a BSSID.
    BOOL currentNetworkInfoCalled = NO, addressCalled = NO;
    NSError *warn;
    NSString *networkID = [NetworkID wifiNetworkIDWithBSSID:nil
                                   currentNetworkInfoBSSIDs:CurrentNetworkInfoBSSIDs(@[@"aa:aa:aa:aa:aa:aa", @"bb:bb:bb:bb:bb:bb"], &currentNetworkInfoCalled)
                                           interfaceAddress:InterfaceAddress(@"192.0.2.1", &addressCalled)
                                                    warning:&warn];
    XCTAssertEqualObjects(networkID, @"WIFI-aa:aa:aa:aa:aa:aa-bb:bb:bb:bb:bb:bb");
    XCTAssertFalse(addressCalled);
}

- (void)testWiFiNetworkIDFallsBackToInterfaceAddress {
    BOOL currentNetworkInfoCalled = NO, addressCalled = NO;
    NSError *warn;
    NSString *networkID = [NetworkID wifiNetworkIDWithBSSID:nil
                                   currentNetworkInfoBSSIDs:CurrentNetworkInfoBSSIDs(@[], &currentNetworkInfoCalled)
                                           interfaceAddress:InterfaceAddress(@"192.0.2.1", &addressCalled)
                                                    warning:&warn];
    XCTAssertEqualObjects(networkID, @"WIFI-192.0.2.1");
    XCTAssertNil(warn);
    XCTAssertTrue(currentNetworkInfoCalled);
    XCTAssertTrue(addressCalled);
}

- (void)testWiFiNetworkIDWithoutAnySource {
    BOOL currentNetworkInfoCalled = NO, addressCalled = NO;
    NSError *warn;
    NSString *networkID = [NetworkID wifiNetworkIDWithBSSID:nil
                                   currentNetworkInfoBSSIDs:CurrentNetworkInfoBSSIDs(@[], &currentNetworkInfoCalled)
                                           interfaceAddress:InterfaceAddress(nil, &addressCalled)
                                                    warning:&warn];
    XCTAssertEqualObjects(networkID, @"WIFI");
    XCTAssertNotNil(warn);
    XCTAssertTrue([warn.localizedDescription containsString:@"no address"], @"%@", warn.localizedDescription);
}

// getNetworkIDWithReachability uses the NEHotspotNetwork BSSID for Wi-Fi only.
- (void)testGetNetworkIDUsesBSSIDOnlyForWiFi {
    if (@available(iOS 12.0, macOS 10.14, *)) {
        DefaultRouteMonitor *reachability = [[DefaultRouteMonitor alloc] init];
        NSError *warn;

        NSString *networkID = [NetworkID getNetworkIDWithReachability:reachability
                                              andCurrentNetworkStatus:NetworkReachabilityReachableViaWiFi
                                                    tunnelWholeDevice:YES
                                                            wifiBSSID:@"e4:38:83:e6:c0:b1"
                                                              warning:&warn];
        XCTAssertEqualObjects(networkID, @"WIFI-e4:38:83:e6:c0:b1");
        XCTAssertNil(warn);

        networkID = [NetworkID getNetworkIDWithReachability:reachability
                                    andCurrentNetworkStatus:NetworkReachabilityReachableViaCellular
                                          tunnelWholeDevice:YES
                                                  wifiBSSID:@"e4:38:83:e6:c0:b1"
                                                    warning:&warn];
        XCTAssertTrue([networkID hasPrefix:@"MOBILE"], @"%@", networkID);
        XCTAssertFalse([networkID containsString:@"e4:38"], @"%@", networkID);
    }
}

@end


/// FakeBSSIDFetcher records fetches so that tests can complete them in any order.
@interface FakeBSSIDFetcher : NSObject
@property (nonatomic) BOOL completesImmediately;
@property (nonatomic, copy, nullable) NSString *immediateBSSID;
@end

@implementation FakeBSSIDFetcher {
    NSLock *lock;
    NSMutableArray<WiFiNetworkInfoFetchCompletion> *completions;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        lock = [[NSLock alloc] init];
        completions = [NSMutableArray array];
    }
    return self;
}

- (WiFiNetworkInfoFetcher)fetcher {
    return ^(WiFiNetworkInfoFetchCompletion completion) {
        [self->lock lock];
        [self->completions addObject:completion];
        BOOL completesImmediately = self.completesImmediately;
        NSString *immediateBSSID = self.immediateBSSID;
        [self->lock unlock];
        if (completesImmediately) {
            completion(immediateBSSID);
        }
    };
}

- (NSUInteger)fetchCount {
    [lock lock];
    NSUInteger count = completions.count;
    [lock unlock];
    return count;
}

- (void)completeFetch:(NSUInteger)index withBSSID:(NSString *_Nullable)bssid {
    [lock lock];
    WiFiNetworkInfoFetchCompletion completion = completions[index];
    [lock unlock];
    completion(bssid);
}

@end

@interface WiFiNetworkInfoTests : XCTestCase
@end

@implementation WiFiNetworkInfoTests {
    FakeBSSIDFetcher *fetcher;
    WiFiNetworkInfo *wifiNetworkInfo;
}

static NSString *const TestBSSID = @"e4:38:83:e6:c0:b1";

- (void)setUp {
    fetcher = [[FakeBSSIDFetcher alloc] init];
    wifiNetworkInfo = [[WiFiNetworkInfo alloc] initWithFetcher:[fetcher fetcher] monitorsPath:NO logger:nil];
}

/// Looks up the BSSID on a background thread, as tunnel-core does, and waits for the result. XCTest runs tests on
/// the main thread, where lookups never wait.
- (NSString *_Nullable)lookupWithTimeout:(NSTimeInterval)timeout elapsed:(NSTimeInterval *_Nullable)outElapsed {
    return [self lookupWithTimeout:timeout elapsed:outElapsed whileRunning:nil];
}

/// As lookupWithTimeout:elapsed:, running action on the calling thread 100 ms after the lookup starts.
- (NSString *_Nullable)lookupWithTimeout:(NSTimeInterval)timeout
                                 elapsed:(NSTimeInterval *_Nullable)outElapsed
                            whileRunning:(void (^_Nullable)(void))action {
    __block NSString *result;
    __block NSTimeInterval elapsed;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    WiFiNetworkInfo *wifiNetworkInfo = self->wifiNetworkInfo;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSTimeInterval start = NSProcessInfo.processInfo.systemUptime;
        result = [wifiNetworkInfo bssidWaitingUpTo:timeout];
        elapsed = NSProcessInfo.processInfo.systemUptime - start;
        dispatch_semaphore_signal(done);
    });
    if (action != nil) {
        [NSThread sleepForTimeInterval:0.1];
        action();
    }
    XCTAssertEqual(dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC)), 0);
    if (outElapsed != NULL) {
        *outElapsed = elapsed;
    }
    return result;
}

- (void)testNotStartedReturnsNilWithoutFetching {
    NSTimeInterval elapsed;
    XCTAssertNil([self lookupWithTimeout:5 elapsed:&elapsed]);
    XCTAssertLessThan(elapsed, 0.5);

    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];
    [wifiNetworkInfo invalidateAndRefetch];
    XCTAssertEqual(fetcher.fetchCount, 0);
}

- (void)testReturnsFetchedBSSID {
    [wifiNetworkInfo start];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];
    XCTAssertEqual(fetcher.fetchCount, 1);

    [fetcher completeFetch:0 withBSSID:TestBSSID];
    XCTAssertEqualObjects([self lookupWithTimeout:5 elapsed:nil], TestBSSID);
    XCTAssertEqualObjects([wifiNetworkInfo bssidWaitingUpTo:5], TestBSSID, @"resolved BSSID not returned on the main thread");

    // Lookups use the cached BSSID.
    XCTAssertEqual(fetcher.fetchCount, 1);
}

- (void)testSynchronousFetcher {
    fetcher.completesImmediately = YES;
    fetcher.immediateBSSID = TestBSSID;
    [wifiNetworkInfo start];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];
    XCTAssertEqualObjects([self lookupWithTimeout:5 elapsed:nil], TestBSSID);
}

- (void)testLookupWaitsForOutstandingFetch {
    [wifiNetworkInfo start];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];

    NSTimeInterval elapsed;
    NSString *bssid = [self lookupWithTimeout:5 elapsed:&elapsed whileRunning:^{
        [self->fetcher completeFetch:0 withBSSID:TestBSSID];
    }];
    XCTAssertEqualObjects(bssid, TestBSSID);
    XCTAssertGreaterThan(elapsed, 0.05);
    XCTAssertLessThan(elapsed, 2);
}

// Before the first path update, the BSSID is pending rather than absent.
- (void)testLookupWaitsForFirstPathUpdate {
    fetcher.completesImmediately = YES;
    fetcher.immediateBSSID = TestBSSID;
    [wifiNetworkInfo start];
    XCTAssertEqual(fetcher.fetchCount, 0);

    NSString *bssid = [self lookupWithTimeout:5 elapsed:nil whileRunning:^{
        [self->wifiNetworkInfo pathUpdatedUsingWiFi:YES];
    }];
    XCTAssertEqualObjects(bssid, TestBSSID);
}

- (void)testStaleResultIsDiscarded {
    [wifiNetworkInfo start];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];
    [fetcher completeFetch:0 withBSSID:TestBSSID];
    XCTAssertEqualObjects([self lookupWithTimeout:5 elapsed:nil], TestBSSID);

    // The network changes. A late result from a fetch made for the new network's predecessor must not be used.
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];
    [wifiNetworkInfo invalidateAndRefetch];
    XCTAssertEqual(fetcher.fetchCount, 3);
    [fetcher completeFetch:1 withBSSID:@"aa:aa:aa:aa:aa:aa"];

    NSString *bssid = [self lookupWithTimeout:5 elapsed:nil whileRunning:^{
        [self->fetcher completeFetch:2 withBSSID:@"bb:bb:bb:bb:bb:bb"];
    }];
    XCTAssertEqualObjects(bssid, @"bb:bb:bb:bb:bb:bb");
}

- (void)testTimeoutAppliesOncePerResult {
    [wifiNetworkInfo start];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];

    NSTimeInterval elapsed;
    XCTAssertNil([self lookupWithTimeout:0.2 elapsed:&elapsed]);
    XCTAssertGreaterThanOrEqual(elapsed, 0.15);

    // A later lookup does not wait for the same outstanding fetch again.
    XCTAssertNil([self lookupWithTimeout:5 elapsed:&elapsed]);
    XCTAssertLessThan(elapsed, 0.5);

    // The late result is still used.
    [fetcher completeFetch:0 withBSSID:TestBSSID];
    XCTAssertEqualObjects([self lookupWithTimeout:5 elapsed:nil], TestBSSID);
}

- (void)testInvalidationAfterTimeoutWaitsAgain {
    [wifiNetworkInfo start];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];
    XCTAssertNil([self lookupWithTimeout:0.1 elapsed:nil]);

    [wifiNetworkInfo invalidateAndRefetch];
    NSString *bssid = [self lookupWithTimeout:5 elapsed:nil whileRunning:^{
        [self->fetcher completeFetch:1 withBSSID:TestBSSID];
    }];
    XCTAssertEqualObjects(bssid, TestBSSID);
}

- (void)testNeverWaitsOnMainThread {
    XCTAssertTrue([NSThread isMainThread]);
    [wifiNetworkInfo start];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];

    NSTimeInterval start = NSProcessInfo.processInfo.systemUptime;
    XCTAssertNil([wifiNetworkInfo bssidWaitingUpTo:5]);
    XCTAssertLessThan(NSProcessInfo.processInfo.systemUptime - start, 0.5);

    // Not waiting on the main thread does not count as a timeout for other threads.
    NSTimeInterval elapsed;
    NSString *bssid = [self lookupWithTimeout:5 elapsed:&elapsed whileRunning:^{
        [self->fetcher completeFetch:0 withBSSID:TestBSSID];
    }];
    XCTAssertEqualObjects(bssid, TestBSSID);
    XCTAssertGreaterThan(elapsed, 0.05);
}

- (void)testNonWiFiPathClearsBSSIDWithoutFetching {
    [wifiNetworkInfo start];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];
    [fetcher completeFetch:0 withBSSID:TestBSSID];
    XCTAssertEqualObjects([self lookupWithTimeout:5 elapsed:nil], TestBSSID);

    [wifiNetworkInfo pathUpdatedUsingWiFi:NO];
    NSTimeInterval elapsed;
    XCTAssertNil([self lookupWithTimeout:5 elapsed:&elapsed]);
    XCTAssertLessThan(elapsed, 0.5);
    XCTAssertEqual(fetcher.fetchCount, 1);
}

// Apps without the entitlement get nil from NEHotspotNetwork. That result is cached, not fetched again per lookup.
- (void)testNilResultIsCached {
    [wifiNetworkInfo start];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];
    [fetcher completeFetch:0 withBSSID:nil];

    for (int i = 0; i < 3; i++) {
        NSTimeInterval elapsed;
        XCTAssertNil([self lookupWithTimeout:5 elapsed:&elapsed]);
        XCTAssertLessThan(elapsed, 0.5);
    }
    XCTAssertEqual(fetcher.fetchCount, 1);
}

- (void)testPlaceholderBSSIDIsRejected {
    [wifiNetworkInfo start];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];
    [fetcher completeFetch:0 withBSSID:@"02:00:00:00:00:00"];
    XCTAssertNil([self lookupWithTimeout:5 elapsed:nil]);
}

- (void)testAcceptedBSSID {
    XCTAssertNil([WiFiNetworkInfo acceptedBSSID:nil]);
    XCTAssertNil([WiFiNetworkInfo acceptedBSSID:@""]);
    for (NSString *placeholder in @[@"00:00:00:00:00:00", @"0:0:0:0:0:0", @"02:00:00:00:00:00", @"2:0:0:0:0:0"]) {
        XCTAssertNil([WiFiNetworkInfo acceptedBSSID:placeholder], @"%@", placeholder);
    }

    // Accepted BSSIDs are returned exactly as reported.
    for (NSString *bssid in @[TestBSSID, @"E4:38:83:E6:C0:B1", @"0:1a:2b:3c:4d:5e"]) {
        XCTAssertEqualObjects([WiFiNetworkInfo acceptedBSSID:bssid], bssid);
    }
}

- (void)testStopReleasesWaitersAndDiscardsResults {
    [wifiNetworkInfo start];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];

    NSTimeInterval elapsed;
    XCTAssertNil([self lookupWithTimeout:5 elapsed:&elapsed whileRunning:^{
        [self->wifiNetworkInfo stop];
    }]);
    XCTAssertLessThan(elapsed, 2);

    [fetcher completeFetch:0 withBSSID:TestBSSID];
    XCTAssertNil([self lookupWithTimeout:5 elapsed:nil]);

    [wifiNetworkInfo invalidateAndRefetch];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];
    XCTAssertEqual(fetcher.fetchCount, 1);

    // Restarting fetches again.
    fetcher.completesImmediately = YES;
    fetcher.immediateBSSID = TestBSSID;
    [wifiNetworkInfo start];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];
    XCTAssertEqualObjects([self lookupWithTimeout:5 elapsed:nil], TestBSSID);
}

- (void)testLogsNeverContainBSSID {
    NSMutableArray<NSString *> *messages = [NSMutableArray array];
    NSLock *messagesLock = [[NSLock alloc] init];
    dispatch_semaphore_t logged = dispatch_semaphore_create(0);
    wifiNetworkInfo = [[WiFiNetworkInfo alloc] initWithFetcher:[fetcher fetcher]
                                                  monitorsPath:NO
                                                        logger:^(NSString * _Nonnull message) {
        [messagesLock lock];
        [messages addObject:message];
        [messagesLock unlock];
        dispatch_semaphore_signal(logged);
    }];

    [wifiNetworkInfo start];
    [wifiNetworkInfo pathUpdatedUsingWiFi:YES];
    XCTAssertNil([self lookupWithTimeout:0.1 elapsed:nil]);
    [fetcher completeFetch:0 withBSSID:TestBSSID];

    // One message for the timeout and one for the fetched BSSID.
    for (int i = 0; i < 2; i++) {
        XCTAssertEqual(dispatch_semaphore_wait(logged, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)), 0);
    }
    [messagesLock lock];
    for (NSString *message in messages) {
        XCTAssertFalse([message.lowercaseString containsString:@"e4:38"], @"%@", message);
    }
    [messagesLock unlock];
}

// The default fetcher must complete, with or without a Wi-Fi network, entitlement or permission. The XCTest host
// has no wifi-info entitlement, so NEHotspotNetwork returns nil here.
- (void)testDefaultFetcherCompletes {
    XCTestExpectation *completed = [self expectationWithDescription:@"completed"];
    [WiFiNetworkInfo defaultFetcher](^(NSString *_Nullable bssid) {
        [completed fulfill];
    });
    [self waitForExpectations:@[completed] timeout:10];
}

@end
