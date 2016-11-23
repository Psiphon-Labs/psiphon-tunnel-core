//
//  PsiphonTunnelTests.m
//  PsiphonTunnelTests
//
//  Created by Adam Pritchard on 2016-10-06.
//  Copyright © 2016 Psiphon Inc. All rights reserved.
//

#import <XCTest/XCTest.h>

#import "PsiphonTunnel.h"


@interface PsiphonTunnelDelegate : NSObject <TunneledAppDelegate>
@end
@implementation PsiphonTunnelDelegate

- (NSString * _Nullable)getPsiphonConfig {
    return @"";
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

@end

