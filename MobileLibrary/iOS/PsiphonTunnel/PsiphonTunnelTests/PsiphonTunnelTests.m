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
static NSString *_Nullable SelectedAddress(FakeInterfaceAddresses *interfaces) {
    const struct ifaddrs *selected = NetworkInterfaceSelectAddress(interfaces.list, "en0");
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
    XCTAssertEqualObjects(SelectedAddress(ipv6Only), @"2001:db8::1");

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
    XCTAssertEqualObjects(SelectedAddress(ipv6Only), @"2001:db8::1");

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

- (void)testSelectsFirstIPv6WithoutIPv4 {
    FakeInterfaceAddresses *interfaces = [[FakeInterfaceAddresses alloc] init];
    [interfaces addLinkLayerInterface:"en0"];
    [interfaces addInterface:"en0" address:"fe80::1"];
    [interfaces addInterface:"en0" address:"2001:db8::1"];
    [interfaces addInterface:"en0" address:"2001:db8::2"];
    XCTAssertEqualObjects(SelectedAddress(interfaces), @"2001:db8::1");
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
    XCTAssertEqualObjects(SelectedAddress(interfaces), @"2001:db8::1");

    XCTAssertTrue(NetworkInterfaceSelectAddress(interfaces.list, NULL) == NULL);
    XCTAssertTrue(NetworkInterfaceSelectAddress(NULL, "en0") == NULL);
}

// getInterfaceAddress formats the address selected from the live interface list.
- (void)testGetInterfaceAddressFormatsSelectedAddress {
    NSError *err;
    NSSet<NSString *> *activeInterfaces = [NetworkInterface activeInterfaces:&err];
    XCTAssertNil(err);

    for (NSString *interfaceName in activeInterfaces) {
        struct ifaddrs *interfaces;
        if (getifaddrs(&interfaces) != 0) {
            XCTFail(@"getifaddrs error with errno %d", errno);
            return;
        }
        const struct ifaddrs *selected = NetworkInterfaceSelectAddress(interfaces,
                                                                       interfaceName.UTF8String);
        NSString *expected = nil;
        if (selected != NULL) {
            char buffer[NI_MAXHOST];
            XCTAssertEqual(getnameinfo(selected->ifa_addr, selected->ifa_addr->sa_len,
                                       buffer, sizeof(buffer), NULL, 0, NI_NUMERICHOST), 0);
            expected = @(buffer);
        }
        freeifaddrs(interfaces);

        NSString *address = [NetworkInterface getInterfaceAddress:interfaceName error:&err];
        XCTAssertNil(err);
        XCTAssertEqualObjects(address, expected, @"%@", interfaceName);
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

/// WiFiReachability reports Wi-Fi with the given path state. NetworkInterface treats the reachability as a
/// DefaultRouteMonitor, so with a nil path state there is no active interface address.
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

@interface NetworkIDTests : XCTestCase
@end

@implementation NetworkIDTests

// tunnelWholeDevice is YES in these tests to skip the VPN network ID check, which depends on the test host.

- (void)testWiFiNetworkIDWithoutActiveInterfaceIsBareWiFi {
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

/// Returns a fake reachability whose active interface is the first live interface, by name, with an address that
/// getInterfaceAddress selects, and sets outAddress to that address. Returns nil if no interface qualifies.
- (WiFiReachability *_Nullable)reachabilityWithAddressedInterface:(NSString **)outAddress {
    NSError *err;
    NSSet<NSString *> *activeInterfaces = [NetworkInterface activeInterfaces:&err];
    XCTAssertNil(err);

    NSArray<NSString *> *names = [activeInterfaces.allObjects sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *interfaceName in names) {
        NSString *address = [NetworkInterface getInterfaceAddress:interfaceName error:&err];
        XCTAssertNil(err);
        if (address != nil) {
            WiFiReachability *reachability = [[WiFiReachability alloc] init];
            reachability.pathState = [[NetworkPathState alloc] initWithNetworkReachability:NetworkReachabilityReachableViaWiFi
                                                                                      path:nil
                                                                defaultActiveInterfaceName:interfaceName];
            *outAddress = address;
            return reachability;
        }
    }
    return nil;
}

- (void)testWiFiNetworkIDIncludesActiveInterfaceAddress {
    NSString *address;
    WiFiReachability *reachability = [self reachabilityWithAddressedInterface:&address];
    if (reachability == nil) {
        XCTSkip(@"no interface with a selectable address");
    }

    NSError *warn;
    NSString *networkID = [NetworkID getNetworkIDWithReachability:reachability
                                          andCurrentNetworkStatus:NetworkReachabilityReachableViaWiFi
                                                tunnelWholeDevice:YES
                                                          warning:&warn];
    XCTAssertEqualObjects(networkID, [@"WIFI-" stringByAppendingString:address]);
    XCTAssertNil(warn);
}

- (void)testWiredNetworkIDIncludesActiveInterfaceAddress {
    NSString *address;
    WiFiReachability *reachability = [self reachabilityWithAddressedInterface:&address];
    if (reachability == nil) {
        XCTSkip(@"no interface with a selectable address");
    }

    NSError *warn;
    NSString *networkID = [NetworkID getNetworkIDWithReachability:reachability
                                          andCurrentNetworkStatus:NetworkReachabilityReachableViaWired
                                                tunnelWholeDevice:YES
                                                          warning:&warn];
    XCTAssertEqualObjects(networkID, [@"WIRED-" stringByAppendingString:address]);
    XCTAssertNil(warn);
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
// the main thread, gets the Wi-Fi network ID. WiFiReachability has no active interface, so it is bare "WIFI".
- (void)testMainThreadStartIsSynchronous {
    XCTAssertTrue([tunnel start:NO]);

    XCTAssertEqual(tunnel.libraryStarts, 1U);
    XCTAssertTrue(tunnel.libraryStartedOnMainThread);
    XCTAssertEqual([tunnel getConnectionState], PsiphonConnectionStateConnecting);
    XCTAssertEqualObjects(tunnel.networkIDAtLibraryStart, @"WIFI");
}

// start: on the main thread returns the result of starting the library.
- (void)testMainThreadStartReturnsLibraryStartFailure {
    tunnel.startSucceeds = NO;

    XCTAssertFalse([tunnel start:NO]);

    XCTAssertEqual(tunnel.libraryStarts, 1U);
    XCTAssertTrue(tunnel.libraryStartedOnMainThread);
}

- (void)testNetworkIDWarningDoesNotBlockLookup {
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
