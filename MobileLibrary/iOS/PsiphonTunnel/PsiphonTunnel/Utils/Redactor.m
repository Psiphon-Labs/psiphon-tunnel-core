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

#import "Redactor.h"

@implementation Redactor

+ (NSString*)stripFilePaths:(NSString*)s {
    return [Redactor stripFilePaths:s withFilePaths:nil];
}

+ (NSString*)stripFilePaths:(NSString*)s withFilePaths:(NSArray<NSString*>*)filePaths {

    NSMutableString *ret = [s mutableCopy];
    NSRange replaceRange = NSMakeRange(0, [ret length]);

    for (NSString *filePath in filePaths) {
        [ret replaceOccurrencesOfString:filePath withString:@"[redacted]"
                                options:kNilOptions range:replaceRange];
    }

    NSString *filePathRegex =
        // File path
        @"("
            // Leading characters
            @"[^ ]*"
            // At least one path separator
            @"/"
            // Path component; take until next space
            @"[^ ]*"
        @")+";

    NSError *err = nil;
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:filePathRegex
                                                                           options:kNilOptions
                                                                             error:&err];
    if (err != nil) {
        [NSException raise:@"Regex compile failed" format:@"failed to compile %@", filePathRegex];
    }

    NSRange searchRange = NSMakeRange(0, [ret length]);
    [regex replaceMatchesInString:ret options:kNilOptions range:searchRange withTemplate:@"[redacted]"];

    return ret;
}

@end
