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

#import "Redactor.h"

@interface RedactorTests : XCTestCase

@end

@implementation RedactorTests

- (void)testRedactor {
    [self run:@"prefix /a suffix" filePaths:nil expect:@"prefix [redacted] suffix"];
    [self run:@"prefix /a/b/c/d suffix" filePaths:nil expect:@"prefix [redacted] suffix"];
    [self run:@"prefix ./a/b/c/d suffix" filePaths:nil expect:@"prefix [redacted] suffix"];
    [self run:@"prefix a/b/c/d suffix" filePaths:nil expect:@"prefix [redacted] suffix"];
    [self run:@"prefix ../a/b/c/d/../ suffix" filePaths:nil expect:@"prefix [redacted] suffix"];
    [self run:@"prefix ~/a/b/c/d suffix" filePaths:nil expect:@"prefix [redacted] suffix"];
    [self run:@"prefix /a/b c/d suffix" filePaths:nil expect:@"prefix [redacted] [redacted] suffix"];
    [self run:@"prefix /a/b%20c/d suffix" filePaths:nil expect:@"prefix [redacted] suffix"];

    // Unhandled case
    [self run:@"prefix /a/file name with spaces /e/f/g/ suffix"
    filePaths:nil
       expect:@"prefix [redacted] name with spaces [redacted] suffix"];

    // Handle unhandled case
    [self run:@"prefix /a/file name with spaces /e/f/g/ suffix"
    filePaths:@[@"/a/file name with spaces"]
       expect:@"prefix [redacted] [redacted] suffix"];
}

- (void)run:(NSString*)input filePaths:(NSArray<NSString*>*)filePaths expect:(NSString*)expect {
    NSString *redacted = [Redactor stripFilePaths:input withFilePaths:filePaths];
    if ([redacted isEqualToString:expect] == false) {
        XCTFail(@"Error: \"%@\" not equal to expect value \"%@\"", redacted, expect);
    }
}

@end
