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
