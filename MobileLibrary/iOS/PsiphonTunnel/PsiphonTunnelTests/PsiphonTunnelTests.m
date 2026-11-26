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

#import "DefaultRouteMonitor.h"
#import "NetworkID.h"
#import "NetworkInterface.h"
#import "PsiphonTunnel.h"

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

/// Returns the value getInterfaceAddress reports for the address NetworkInterfaceSelectAddress selects for the named
/// interface: the IPv4 address, or the IPv6 /32 prefix. Returns nil if none is selected.
static NSString *_Nullable FormatSelectedAddress(const struct ifaddrs *_Nullable interfaces, const char *name) {
    const struct ifaddrs *selected = NetworkInterfaceSelectAddress(interfaces, name);
    if (selected == NULL) {
        return nil;
    }
    const struct sockaddr *addr = selected->ifa_addr;
    if (addr->sa_family == AF_INET6) {
        return NetworkInterfaceFormatIPv6Prefix(&((const struct sockaddr_in6 *)addr)->sin6_addr);
    }
    char buffer[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &((const struct sockaddr_in *)addr)->sin_addr, buffer, sizeof(buffer)) == NULL) {
        return nil;
    }
    return @(buffer);
}

/// Returns FormatSelectedAddress for en0.
static NSString *_Nullable SelectedAddress(FakeInterfaceAddresses *interfaces) {
    return FormatSelectedAddress(interfaces.list, "en0");
}

/// Returns NetworkInterfaceFormatIPv6Prefix for an IPv6 literal.
static NSString *FormatIPv6Prefix(const char *address) {
    struct in6_addr addr;
    if (inet_pton(AF_INET6, address, &addr) != 1) {
        [NSException raise:NSInvalidArgumentException format:@"invalid address %s", address];
    }
    return NetworkInterfaceFormatIPv6Prefix(&addr);
}

@interface NetworkInterfaceTests : XCTestCase
@end

@implementation NetworkInterfaceTests

- (void)testSelectsIPv4RegardlessOfOrder {
    FakeInterfaceAddresses *ipv6First = [[FakeInterfaceAddresses alloc] init];
    [ipv6First addLinkLayerInterface:"en0"];
    [ipv6First addInterface:"en0" address:"fe80::1"];
    [ipv6First addInterface:"en0" address:"2001:db8::1"];
    [ipv6First addInterface:"en0" address:"2001:db8::2"];
    [ipv6First addInterface:"en0" address:"192.0.2.1"];
    XCTAssertEqualObjects(SelectedAddress(ipv6First), @"192.0.2.1");

    FakeInterfaceAddresses *ipv4First = [[FakeInterfaceAddresses alloc] init];
    [ipv4First addInterface:"en0" address:"192.0.2.1"];
    [ipv4First addInterface:"en0" address:"2001:db8::1"];
    XCTAssertEqualObjects(SelectedAddress(ipv4First), @"192.0.2.1");

    FakeInterfaceAddresses *twoIPv4 = [[FakeInterfaceAddresses alloc] init];
    [twoIPv4 addInterface:"en0" address:"2001:db8::1"];
    [twoIPv4 addInterface:"en0" address:"192.0.2.1"];
    [twoIPv4 addInterface:"en0" address:"192.0.2.2"];
    XCTAssertEqualObjects(SelectedAddress(twoIPv4), @"192.0.2.1");

    // IPv4 is also preferred over a unique local IPv6 address.
    FakeInterfaceAddresses *withUniqueLocal = [[FakeInterfaceAddresses alloc] init];
    [withUniqueLocal addInterface:"en0" address:"fd12:3456:789a:1::5"];
    [withUniqueLocal addInterface:"en0" address:"2001:db8::1"];
    [withUniqueLocal addInterface:"en0" address:"203.0.113.7"];
    XCTAssertEqualObjects(SelectedAddress(withUniqueLocal), @"203.0.113.7");
}

- (void)testSkipsLinkLocal {
    FakeInterfaceAddresses *withIPv4 = [[FakeInterfaceAddresses alloc] init];
    [withIPv4 addInterface:"en0" address:"fe80::1"];
    [withIPv4 addInterface:"en0" address:"169.254.1.1"];
    [withIPv4 addInterface:"en0" address:"192.0.2.1"];
    XCTAssertEqualObjects(SelectedAddress(withIPv4), @"192.0.2.1");

    // A self-assigned IPv4 address alongside a global IPv6 address, as on an IPv6-only network.
    FakeInterfaceAddresses *ipv6Only = [[FakeInterfaceAddresses alloc] init];
    [ipv6Only addInterface:"en0" address:"169.254.1.1"];
    [ipv6Only addInterface:"en0" address:"fe80::1"];
    [ipv6Only addInterface:"en0" address:"2001:db8::1"];
    XCTAssertEqualObjects(SelectedAddress(ipv6Only), @"2001:db8::/32");

    FakeInterfaceAddresses *linkLocalOnly = [[FakeInterfaceAddresses alloc] init];
    [linkLocalOnly addInterface:"en0" address:"169.254.1.1"];
    [linkLocalOnly addInterface:"en0" address:"fe80::1"];
    XCTAssertNil(SelectedAddress(linkLocalOnly));
}

- (void)testSkips464XLAT {
    // The 464XLAT address alongside a global IPv6 address, as on an IPv6-only cellular or IPv6-mostly
    // Wi-Fi network.
    FakeInterfaceAddresses *ipv6Only = [[FakeInterfaceAddresses alloc] init];
    [ipv6Only addInterface:"en0" address:"192.0.0.2"];
    [ipv6Only addInterface:"en0" address:"fe80::1"];
    [ipv6Only addInterface:"en0" address:"2001:db8::1"];
    XCTAssertEqualObjects(SelectedAddress(ipv6Only), @"2001:db8::/32");

    FakeInterfaceAddresses *withIPv4 = [[FakeInterfaceAddresses alloc] init];
    [withIPv4 addInterface:"en0" address:"192.0.0.2"];
    [withIPv4 addInterface:"en0" address:"192.0.2.1"];
    XCTAssertEqualObjects(SelectedAddress(withIPv4), @"192.0.2.1");

    FakeInterfaceAddresses *xlatOnly = [[FakeInterfaceAddresses alloc] init];
    [xlatOnly addInterface:"en0" address:"192.0.0.0"];
    [xlatOnly addInterface:"en0" address:"192.0.0.2"];
    [xlatOnly addInterface:"en0" address:"192.0.0.7"];
    XCTAssertNil(SelectedAddress(xlatOnly));

    // Addresses just outside 192.0.0.0/29 are selected.
    FakeInterfaceAddresses *outsideAbove = [[FakeInterfaceAddresses alloc] init];
    [outsideAbove addInterface:"en0" address:"192.0.0.8"];
    XCTAssertEqualObjects(SelectedAddress(outsideAbove), @"192.0.0.8");

    FakeInterfaceAddresses *outsideBelow = [[FakeInterfaceAddresses alloc] init];
    [outsideBelow addInterface:"en0" address:"191.255.255.255"];
    XCTAssertEqualObjects(SelectedAddress(outsideBelow), @"191.255.255.255");
}

- (void)testSelectsLowestIPv6PrefixRegardlessOfOrder {
    FakeInterfaceAddresses *lowestLast = [[FakeInterfaceAddresses alloc] init];
    [lowestLast addLinkLayerInterface:"en0"];
    [lowestLast addInterface:"en0" address:"fe80::1"];
    [lowestLast addInterface:"en0" address:"2a00:1450::1"];
    [lowestLast addInterface:"en0" address:"2607:fb90:1234::1"];
    [lowestLast addInterface:"en0" address:"2001:db8:85a3::1"];
    XCTAssertEqualObjects(SelectedAddress(lowestLast), @"2001:db8::/32");

    FakeInterfaceAddresses *lowestFirst = [[FakeInterfaceAddresses alloc] init];
    [lowestFirst addInterface:"en0" address:"2001:db8:85a3::1"];
    [lowestFirst addInterface:"en0" address:"2607:fb90:1234::1"];
    [lowestFirst addInterface:"en0" address:"2a00:1450::1"];
    XCTAssertEqualObjects(SelectedAddress(lowestFirst), @"2001:db8::/32");

    // The same holds within the unique local class.
    FakeInterfaceAddresses *uniqueLocal = [[FakeInterfaceAddresses alloc] init];
    [uniqueLocal addInterface:"en0" address:"fdff:ffff::1"];
    [uniqueLocal addInterface:"en0" address:"fd12:3456:789a:1::5"];
    [uniqueLocal addInterface:"en0" address:"fc00:1::1"];
    [uniqueLocal addInterface:"en0" address:"fd12:3455:ffff::1"];
    XCTAssertEqualObjects(SelectedAddress(uniqueLocal), @"fc00:1::/32");
}

- (void)testPrefersUniqueLocalIPv6RegardlessOfOrder {
    FakeInterfaceAddresses *uniqueLocalLast = [[FakeInterfaceAddresses alloc] init];
    [uniqueLocalLast addInterface:"en0" address:"2001:db8::1"];
    [uniqueLocalLast addInterface:"en0" address:"2607:fb90:1234::1"];
    [uniqueLocalLast addInterface:"en0" address:"fd12:3456:789a:1::5"];
    XCTAssertEqualObjects(SelectedAddress(uniqueLocalLast), @"fd12:3456::/32");

    FakeInterfaceAddresses *uniqueLocalFirst = [[FakeInterfaceAddresses alloc] init];
    [uniqueLocalFirst addInterface:"en0" address:"fd12:3456:789a:1::5"];
    [uniqueLocalFirst addInterface:"en0" address:"2001:db8::1"];
    [uniqueLocalFirst addInterface:"en0" address:"2607:fb90:1234::1"];
    XCTAssertEqualObjects(SelectedAddress(uniqueLocalFirst), @"fd12:3456::/32");
}

- (void)testIgnoresIPv6OutsideUniqueLocalAndGlobal {
    FakeInterfaceAddresses *interfaces = [[FakeInterfaceAddresses alloc] init];
    [interfaces addInterface:"en0" address:"::"];
    [interfaces addInterface:"en0" address:"::1"];
    [interfaces addInterface:"en0" address:"::ffff:192.0.2.1"];
    [interfaces addInterface:"en0" address:"1fff:ffff::1"];
    [interfaces addInterface:"en0" address:"4000::1"];
    [interfaces addInterface:"en0" address:"fbff:ffff::1"];
    [interfaces addInterface:"en0" address:"fe00::1"];
    [interfaces addInterface:"en0" address:"fe80::1"];
    [interfaces addInterface:"en0" address:"fec0::1"];
    [interfaces addInterface:"en0" address:"ff02::1"];
    XCTAssertNil(SelectedAddress(interfaces));

    // The highest global unicast address qualifies; the out-of-range addresses are still ignored, although
    // several of them are numerically lower.
    [interfaces addInterface:"en0" address:"3fff:ffff::1"];
    XCTAssertEqualObjects(SelectedAddress(interfaces), @"3fff:ffff::/32");

    FakeInterfaceAddresses *lowestGlobal = [[FakeInterfaceAddresses alloc] init];
    [lowestGlobal addInterface:"en0" address:"1fff:ffff::1"];
    [lowestGlobal addInterface:"en0" address:"2000::1"];
    XCTAssertEqualObjects(SelectedAddress(lowestGlobal), @"2000:0::/32");

    FakeInterfaceAddresses *uniqueLocalBounds = [[FakeInterfaceAddresses alloc] init];
    [uniqueLocalBounds addInterface:"en0" address:"fe00::1"];
    [uniqueLocalBounds addInterface:"en0" address:"fdff:ffff::1"];
    XCTAssertEqualObjects(SelectedAddress(uniqueLocalBounds), @"fdff:ffff::/32");
}

- (void)testFormatIPv6Prefix {
    XCTAssertEqualObjects(FormatIPv6Prefix("2001:0db8:85a3::1"), @"2001:db8::/32");
    XCTAssertEqualObjects(FormatIPv6Prefix("fd12:3456:789a:1::5"), @"fd12:3456::/32");
    XCTAssertEqualObjects(FormatIPv6Prefix("2607:fb90:1234::1"), @"2607:fb90::/32");
    XCTAssertEqualObjects(FormatIPv6Prefix("2001:0000:1::1"), @"2001:0::/32");
    XCTAssertEqualObjects(FormatIPv6Prefix("2a00:0001:2:3:4:5:6:7"), @"2a00:1::/32");
    XCTAssertEqualObjects(FormatIPv6Prefix("FFFF:FFFF:FFFF::"), @"ffff:ffff::/32");
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
    XCTAssertEqualObjects(SelectedAddress(interfaces), @"2001:db8::/32");

    XCTAssertTrue(NetworkInterfaceSelectAddress(interfaces.list, NULL) == NULL);
    XCTAssertTrue(NetworkInterfaceSelectAddress(NULL, "en0") == NULL);
}

/// Returns FormatSelectedAddress for one live getifaddrs(3) snapshot. Sets outOK to NO if getifaddrs fails.
static NSString *_Nullable LiveSelectedAddress(NSString *interfaceName, BOOL *outOK) {
    struct ifaddrs *interfaces;
    *outOK = getifaddrs(&interfaces) == 0;
    if (!*outOK) {
        return nil;
    }
    NSString *address = FormatSelectedAddress(interfaces, interfaceName.UTF8String);
    freeifaddrs(interfaces);
    return address;
}

// getInterfaceAddress formats the address selected from the live interface list. The selection is read before and
// after getInterfaceAddress, and an interface whose selection changed in between is not checked.
- (void)testGetInterfaceAddressFormatsSelectedAddress {
    NSError *err;
    NSSet<NSString *> *activeInterfaces = [NetworkInterface activeInterfaces:&err];
    XCTAssertNil(err);

    for (NSString *interfaceName in activeInterfaces) {
        BOOL beforeOK, afterOK;
        NSString *before = LiveSelectedAddress(interfaceName, &beforeOK);
        NSString *address = [NetworkInterface getInterfaceAddress:interfaceName error:&err];
        XCTAssertNil(err);
        NSString *after = LiveSelectedAddress(interfaceName, &afterOK);
        if (!beforeOK || !afterOK) {
            XCTFail(@"getifaddrs failed");
            return;
        }
        if (before != after && ![before isEqualToString:after]) {
            continue;
        }
        XCTAssertEqualObjects(address, before, @"%@", interfaceName);
    }

    XCTAssertNil([NetworkInterface getInterfaceAddress:@"lo0" error:&err]);
    XCTAssertNil(err);
}

@end


@interface NetworkPathState (Testing)
- (instancetype)initWithNetworkReachability:(NetworkReachability)networkReachability
                                       path:(nw_path_t _Nullable)path
                 defaultActiveInterfaceName:(NSString *_Nullable)defaultActiveInterfaceName;
@end

/// WiFiReachability reports Wi-Fi as its reachabilityStatus, with the given path state. NetworkID treats the
/// reachability as a DefaultRouteMonitor, so with a nil path state there is no active interface address, and with a
/// non-nil one the network type is the path state's status.
@interface WiFiReachability : NSObject <ReachabilityProtocol>
@property (atomic, nullable) NetworkPathState *pathState;
@end

@implementation WiFiReachability
+ (NSString *)reachabilityChangedNotification {
    return @"WiFiReachabilityChanged";
}
- (BOOL)startNotifier {
    return YES;
}
- (void)stopNotifier {
}
- (NetworkReachability)reachabilityStatus {
    return NetworkReachabilityReachableViaWiFi;
}
- (NSString *)reachabilityStatusDebugInfo {
    return @"Wi-Fi";
}
@end

/// PathStateSequenceReachability returns the next of pathStates on each read of pathState, repeating the last one,
/// and counts the reads.
@interface PathStateSequenceReachability : WiFiReachability
@property (atomic, copy) NSArray<NetworkPathState *> *pathStates;
@property (atomic) NSUInteger pathStateReads;
@end

@implementation PathStateSequenceReachability
- (NetworkPathState *)pathState {
    NSArray<NetworkPathState *> *states = self.pathStates;
    NSUInteger reads = self.pathStateReads;
    self.pathStateReads = reads + 1;
    return states[MIN(reads, states.count - 1)];
}
@end

/// Returns YES if NetworkID takes the network type and active interface from the reachability's path state, as on
/// iOS 12 and later. Before iOS 12, NetworkID ignores the path state and uses the status argument and the live
/// interfaces.
static BOOL NetworkIDUsesPathState(void) {
    if (@available(iOS 12.0, *)) {
        return YES;
    }
    return NO;
}

static NSString *const NetworkIDUsesPathStateSkipReason =
    @"the network type and active interface come from the path state only on iOS 12 and later";

@interface NetworkIDTests : XCTestCase
@end

@implementation NetworkIDTests

// tunnelWholeDevice is YES in these tests to skip the VPN network ID check, which depends on the test host.

- (void)testWiFiNetworkIDWithoutActiveInterfaceIsBareWiFi {
    if (!NetworkIDUsesPathState()) {
        XCTSkip(@"%@", NetworkIDUsesPathStateSkipReason);
    }

    NSError *warn;
    NSString *networkID = [NetworkID getNetworkIDWithReachability:[[WiFiReachability alloc] init]
                                          andCurrentNetworkStatus:NetworkReachabilityReachableViaWiFi
                                                tunnelWholeDevice:YES
                                                          warning:&warn];
    XCTAssertEqualObjects(networkID, @"WIFI");
    XCTAssertNotNil(warn);
    XCTAssertTrue([warn.localizedDescription containsString:@"network path state nil"], @"%@", warn.localizedDescription);
}

- (void)testWiFiNetworkIDWithoutInterfaceAddressIsBareWiFi {
    if (!NetworkIDUsesPathState()) {
        XCTSkip(@"%@", NetworkIDUsesPathStateSkipReason);
    }

    WiFiReachability *reachability = [[WiFiReachability alloc] init];
    // No interface has this name, so the active interface has no address.
    reachability.pathState = [[NetworkPathState alloc] initWithNetworkReachability:NetworkReachabilityReachableViaWiFi
                                                                              path:nil
                                                        defaultActiveInterfaceName:@"psiphontest0"];
    NSError *warn;
    NSString *networkID = [NetworkID getNetworkIDWithReachability:reachability
                                          andCurrentNetworkStatus:NetworkReachabilityReachableViaWiFi
                                                tunnelWholeDevice:YES
                                                          warning:&warn];
    XCTAssertEqualObjects(networkID, @"WIFI");
    XCTAssertNotNil(warn);
    XCTAssertTrue([warn.localizedDescription containsString:@"interface address nil"], @"%@", warn.localizedDescription);
}

/// Returns the first live interface, by name, with an address that getInterfaceAddress selects, and sets outAddress
/// to the value getInterfaceAddress returns for it: an IPv4 address or an IPv6 /32 prefix. Returns nil if no
/// interface qualifies.
- (NSString *_Nullable)addressedInterface:(NSString **)outAddress {
    NSError *err;
    NSSet<NSString *> *activeInterfaces = [NetworkInterface activeInterfaces:&err];
    XCTAssertNil(err);

    NSArray<NSString *> *names = [activeInterfaces.allObjects sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *interfaceName in names) {
        NSString *address = [NetworkInterface getInterfaceAddress:interfaceName error:&err];
        XCTAssertNil(err);
        if (address != nil) {
            // tunnel-core treats everything after the first "-" in a network ID as private.
            XCTAssertFalse([address containsString:@"-"], @"%@", address);
            *outAddress = address;
            return interfaceName;
        }
    }
    return nil;
}

/// Returns a fake reachability whose path state has the given status and, as its active interface,
/// addressedInterface. Returns nil if no interface qualifies.
- (WiFiReachability *_Nullable)reachabilityWithStatus:(NetworkReachability)status
                                   addressedInterface:(NSString **)outAddress {
    NSString *interfaceName = [self addressedInterface:outAddress];
    if (interfaceName == nil) {
        return nil;
    }
    WiFiReachability *reachability = [[WiFiReachability alloc] init];
    reachability.pathState = [[NetworkPathState alloc] initWithNetworkReachability:status
                                                                              path:nil
                                                        defaultActiveInterfaceName:interfaceName];
    return reachability;
}

/// Checks that the network ID for a path state with the given status and an addressed interface is the type followed
/// by the interface's address. A mismatch is tolerated only if the interface's address has since changed.
- (void)assertNetworkIDWithStatus:(NetworkReachability)status includesActiveInterfaceAddressAfterType:(NSString *)type {
    if (!NetworkIDUsesPathState()) {
        XCTSkip(@"%@", NetworkIDUsesPathStateSkipReason);
    }

    NSString *address;
    WiFiReachability *reachability = [self reachabilityWithStatus:status addressedInterface:&address];
    if (reachability == nil) {
        XCTSkip(@"no interface with a selectable address");
    }

    NSError *warn;
    NSString *networkID = [NetworkID getNetworkIDWithReachability:reachability
                                          andCurrentNetworkStatus:status
                                                tunnelWholeDevice:YES
                                                          warning:&warn];
    NSString *expected = [NSString stringWithFormat:@"%@-%@", type, address];
    if (![networkID isEqualToString:expected]) {
        NSString *interfaceName = reachability.pathState.defaultActiveInterfaceName;
        NSError *err;
        NSString *currentAddress = [NetworkInterface getInterfaceAddress:interfaceName error:&err];
        XCTAssertNil(err);
        if (![currentAddress isEqualToString:address]) {
            XCTSkip(@"%@ address changed during the test", interfaceName);
        }
    }
    XCTAssertEqualObjects(networkID, expected);
    XCTAssertNil(warn);
}

- (void)testWiFiNetworkIDIncludesActiveInterfaceAddress {
    [self assertNetworkIDWithStatus:NetworkReachabilityReachableViaWiFi includesActiveInterfaceAddressAfterType:@"WIFI"];
}

- (void)testWiredNetworkIDIncludesActiveInterfaceAddress {
    [self assertNetworkIDWithStatus:NetworkReachabilityReachableViaWired
        includesActiveInterfaceAddressAfterType:@"WIRED"];
}

// The tests below construct their path states, so they do not depend on the host's interfaces. No interface has the
// name psiphontest0, so an address-based network ID for it is the bare type with an "interface address nil"
// warning; a nil interface name gives a "no active interface" warning instead.

/// Returns a fake reachability whose path state has the given status and active interface name.
static WiFiReachability *ReachabilityWithPathState(NetworkReachability status, NSString *_Nullable interfaceName) {
    WiFiReachability *reachability = [[WiFiReachability alloc] init];
    reachability.pathState = [[NetworkPathState alloc] initWithNetworkReachability:status
                                                                              path:nil
                                                        defaultActiveInterfaceName:interfaceName];
    return reachability;
}

// The network type comes from the path state, not from a status argument that lags it during a handoff.
- (void)testNetworkIDTypeComesFromPathStateNotStaleStatus {
    if (!NetworkIDUsesPathState()) {
        XCTSkip(@"%@", NetworkIDUsesPathStateSkipReason);
    }

    NSError *warn;
    NSString *networkID =
        [NetworkID getNetworkIDWithReachability:ReachabilityWithPathState(NetworkReachabilityReachableViaWired, @"psiphontest0")
                        andCurrentNetworkStatus:NetworkReachabilityReachableViaWiFi
                              tunnelWholeDevice:YES
                                        warning:&warn];
    XCTAssertEqualObjects(networkID, @"WIRED");
    XCTAssertTrue([warn.localizedDescription containsString:@"interface address nil"], @"%@", warn.localizedDescription);

    networkID =
        [NetworkID getNetworkIDWithReachability:ReachabilityWithPathState(NetworkReachabilityReachableViaWiFi, @"psiphontest0")
                        andCurrentNetworkStatus:NetworkReachabilityReachableViaWired
                              tunnelWholeDevice:YES
                                        warning:&warn];
    XCTAssertEqualObjects(networkID, @"WIFI");
    XCTAssertTrue([warn.localizedDescription containsString:@"interface address nil"], @"%@", warn.localizedDescription);
}

- (void)testNotReachablePathStateIsUnknown {
    if (!NetworkIDUsesPathState()) {
        XCTSkip(@"%@", NetworkIDUsesPathStateSkipReason);
    }

    NetworkReachability statuses[] = {
        NetworkReachabilityNotReachable,
        NetworkReachabilityReachableViaWiFi,
        NetworkReachabilityReachableViaCellular,
        NetworkReachabilityReachableViaWired,
        NetworkReachabilityReachableViaLoopback,
        NetworkReachabilityReachableViaUnknown,
    };
    NSArray *interfaceNames = @[@"psiphontest0", [NSNull null]];
    for (id interfaceName in interfaceNames) {
        WiFiReachability *reachability =
            ReachabilityWithPathState(NetworkReachabilityNotReachable, interfaceName == [NSNull null] ? nil : interfaceName);
        for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
            NSError *warn;
            NSString *networkID = [NetworkID getNetworkIDWithReachability:reachability
                                                  andCurrentNetworkStatus:statuses[i]
                                                        tunnelWholeDevice:YES
                                                                  warning:&warn];
            XCTAssertEqualObjects(networkID, @"UNKNOWN", @"%@, status %ld", interfaceName, (long)statuses[i]);
            XCTAssertNil(warn, @"%@, status %ld", interfaceName, (long)statuses[i]);
        }
    }
}

// One lookup reads the path state once, so the type and the interface name come from the same observation even if
// the monitor's state changes during the lookup.
- (void)testNetworkIDReadsPathStateOnce {
    if (!NetworkIDUsesPathState()) {
        XCTSkip(@"%@", NetworkIDUsesPathStateSkipReason);
    }

    PathStateSequenceReachability *reachability = [[PathStateSequenceReachability alloc] init];
    // The two states give different types and different warnings, so a second read for the interface would show.
    reachability.pathStates = @[
        [[NetworkPathState alloc] initWithNetworkReachability:NetworkReachabilityReachableViaWired
                                                         path:nil
                                   defaultActiveInterfaceName:nil],
        [[NetworkPathState alloc] initWithNetworkReachability:NetworkReachabilityReachableViaWiFi
                                                         path:nil
                                   defaultActiveInterfaceName:@"psiphontest0"],
    ];

    NSError *warn;
    NSString *networkID = [NetworkID getNetworkIDWithReachability:reachability
                                          andCurrentNetworkStatus:NetworkReachabilityReachableViaWiFi
                                                tunnelWholeDevice:YES
                                                          warning:&warn];
    XCTAssertEqualObjects(networkID, @"WIRED");
    XCTAssertTrue([warn.localizedDescription containsString:@"no active interface"], @"%@", warn.localizedDescription);
    XCTAssertFalse([warn.localizedDescription containsString:@"interface address nil"], @"%@", warn.localizedDescription);
    XCTAssertEqual(reachability.pathStateReads, 1U);
}

// Before iOS 12, the network type comes from the status argument, and the path state is not read even if it
// conflicts with the status.
- (void)testLegacyNetworkIDIgnoresPathState {
    if (NetworkIDUsesPathState()) {
        XCTSkip(@"the path state is ignored only before iOS 12");
    }

    PathStateSequenceReachability *reachability = [[PathStateSequenceReachability alloc] init];
    reachability.pathStates = @[
        [[NetworkPathState alloc] initWithNetworkReachability:NetworkReachabilityReachableViaWiFi
                                                         path:nil
                                   defaultActiveInterfaceName:@"psiphontest0"],
    ];

    NSError *warn;
    NSString *networkID = [NetworkID getNetworkIDWithReachability:reachability
                                          andCurrentNetworkStatus:NetworkReachabilityNotReachable
                                                tunnelWholeDevice:YES
                                                          warning:&warn];
    XCTAssertEqualObjects(networkID, @"UNKNOWN");
    XCTAssertNil(warn);
    XCTAssertEqual(reachability.pathStateReads, 0U);
}

@end


#if TARGET_OS_IPHONE
@interface PsiphonTunnel (StartTesting)
- (NSString *)getConfig:(BOOL *)usingNoticeFiles error:(NSError **)err;
- (void)logMessage:(NSString *)message;
- (BOOL)startPsiphonLibraryWithConfig:(NSString *)configStr
                embeddedServerEntries:(NSString *)embeddedServerEntries
            embeddedServerEntriesPath:(NSString *)embeddedServerEntriesPath
                     usingNoticeFiles:(BOOL)usingNoticeFiles;
- (NSString *)getNetworkID;
@end

/// StartTestTunnel replaces only GoPsiStart. In its place, it requests the network ID as tunnel-core first does
/// during GoPsiStart, on the same thread, and records what it observed.
@interface StartTestTunnel : PsiphonTunnel
@property (atomic) BOOL startSucceeds;
@property (atomic) NSUInteger libraryStarts;
@property (atomic) BOOL libraryStartedOnMainThread;
@property (atomic, copy) NSString *networkIDAtLibraryStart;
@property (atomic, copy) void (^onNetworkIDWarning)(NSString *message);
@end

@implementation StartTestTunnel
- (void)logMessage:(NSString *)message {
    void (^handler)(NSString *) = self.onNetworkIDWarning;
    if (handler != nil && [message hasPrefix:@"error getting network ID:"]) {
        handler(message);
    } else {
        [super logMessage:message];
    }
}

- (NSString *)getConfig:(BOOL *)usingNoticeFiles error:(NSError **)err {
    *usingNoticeFiles = NO;
    *err = nil;
    return @"{}";
}

- (BOOL)startPsiphonLibraryWithConfig:(NSString *)configStr
                embeddedServerEntries:(NSString *)embeddedServerEntries
            embeddedServerEntriesPath:(NSString *)embeddedServerEntriesPath
                     usingNoticeFiles:(BOOL)usingNoticeFiles {
    self.libraryStartedOnMainThread = [NSThread isMainThread];
    self.networkIDAtLibraryStart = [self getNetworkID];
    self.libraryStarts++;
    return self.startSucceeds;
}
@end

@interface PsiphonTunnelStartTests : XCTestCase
@end

@implementation PsiphonTunnelStartTests {
    StartTestTunnel *tunnel;
}

- (void)setUp {
    [super setUp];
    XCTAssertTrue([NSThread isMainThread]);
    tunnel = [[StartTestTunnel alloc] init];
    tunnel.startSucceeds = YES;
    [tunnel setValue:[[WiFiReachability alloc] init] forKey:@"reachability"];
    // Skip the VPN network ID check, which depends on the test host.
    [tunnel setValue:@YES forKey:@"tunnelWholeDevice"];
}

- (void)tearDown {
    [tunnel stop];
    [super tearDown];
}

// start: on the main thread starts the library before returning, and tunnel-core's first network ID request, on
// the main thread, gets the Wi-Fi network ID. WiFiReachability has no path state, so from iOS 12 it is bare "WIFI";
// before iOS 12 the live interfaces are used, so it can also be "WIFI-" followed by an address.
- (void)testMainThreadStartIsSynchronous {
    XCTAssertTrue([tunnel start:NO]);

    XCTAssertEqual(tunnel.libraryStarts, 1U);
    XCTAssertTrue(tunnel.libraryStartedOnMainThread);
    XCTAssertEqual([tunnel getConnectionState], PsiphonConnectionStateConnecting);
    NSString *networkID = tunnel.networkIDAtLibraryStart;
    if (NetworkIDUsesPathState()) {
        XCTAssertEqualObjects(networkID, @"WIFI");
    } else {
        BOOL isWiFi = [networkID isEqualToString:@"WIFI"] ||
            ([networkID hasPrefix:@"WIFI-"] && networkID.length > @"WIFI-".length);
        XCTAssertTrue(isWiFi, @"%@", networkID);
    }
}

// start: on the main thread returns the result of starting the library.
- (void)testMainThreadStartReturnsLibraryStartFailure {
    tunnel.startSucceeds = NO;

    XCTAssertFalse([tunnel start:NO]);

    XCTAssertEqual(tunnel.libraryStarts, 1U);
    XCTAssertTrue(tunnel.libraryStartedOnMainThread);
}

- (void)testNetworkIDWarningDoesNotBlockLookup {
    // Before iOS 12 the lookup uses the live interfaces, so it may not warn.
    if (!NetworkIDUsesPathState()) {
        XCTSkip(@"%@", NetworkIDUsesPathStateSkipReason);
    }

    XCTestExpectation *logged = [self expectationWithDescription:@"network ID warning delivered"];
    NSLock *providerLock = [[NSLock alloc] init];
    tunnel.onNetworkIDWarning = ^(NSString *message) {
        // Go holds its provider mutex across getNetworkID. Notice delivery can need that mutex, so logging
        // must not prevent the lookup from returning and releasing it. Bound this wait so a regression fails
        // the test rather than hanging the test process.
        BOOL acquired = [providerLock lockBeforeDate:[NSDate dateWithTimeIntervalSinceNow:5]];
        XCTAssertTrue(acquired, @"warning logging blocked the network ID lookup");
        if (acquired) {
            [providerLock unlock];
        }
        [logged fulfill];
    };

    [providerLock lock];
    BOOL started = [tunnel start:NO];
    [providerLock unlock];

    XCTAssertTrue(started);
    XCTAssertEqualObjects(tunnel.networkIDAtLibraryStart, @"WIFI");
    [self waitForExpectations:@[logged] timeout:5];
}

@end
#endif
