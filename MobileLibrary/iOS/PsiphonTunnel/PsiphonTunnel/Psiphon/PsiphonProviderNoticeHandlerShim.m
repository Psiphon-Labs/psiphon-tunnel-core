/*
 * Copyright (c) 2020, Psiphon Inc.
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

#import "PsiphonProviderNoticeHandlerShim.h"

@implementation PsiphonProviderNoticeHandlerShim {
    void (^logger) (NSString *_Nonnull);
}

- (id)initWithLogger:(void (^__nonnull)(NSString *_Nonnull))logger {
    self = [super init];
    if (self != nil) {
        self->logger = logger;
    }
    return self;
}

#pragma mark - GoPsiPsiphonProviderNoticeHandler implementation

- (void)notice:(NSString *)noticeJSON {
    if (self->logger != nil) {
        self->logger(noticeJSON);
    }
}

@end
