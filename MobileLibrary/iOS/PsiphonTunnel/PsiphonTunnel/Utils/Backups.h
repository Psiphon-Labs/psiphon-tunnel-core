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

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface Backups : NSObject

/// Excludes the target file from application backups made by iCloud and iTunes.
/// If false is returned, the file was not successfully excluded from backup and the error is populated.
/// @param filePath Path at which the file exists.
/// @param err If non-nil, contains the error encountered when attempting to exclude the file from backup.
/// @return If true, then the operation succeeded. If false, then the file was not successfully excluded from
/// backup and the error is populated.
+ (BOOL)excludeFileFromBackup:(NSString*)filePath err:(NSError * _Nullable *)err;

@end

NS_ASSUME_NONNULL_END
