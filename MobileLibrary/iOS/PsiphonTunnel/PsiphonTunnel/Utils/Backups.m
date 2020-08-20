/*
 * Copyright (c) 2019, Psiphon Inc.
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

#import "Backups.h"

@implementation Backups

// See comment in header
+ (BOOL)excludeFileFromBackup:(NSString*)filePath err:(NSError**)err {
    *err = nil;

    // The URL must be of the file scheme ("file://"), otherwise the `setResourceValue:forKey:error`
    // operation will silently fail with: "CFURLCopyResourcePropertyForKey failed because passed URL
    // no scheme".
    NSURL *urlWithScheme = [NSURL fileURLWithPath:filePath];

    return [urlWithScheme setResourceValue:[NSNumber numberWithBool:YES]
                                    forKey:NSURLIsExcludedFromBackupKey
                                     error:err];
}

@end
