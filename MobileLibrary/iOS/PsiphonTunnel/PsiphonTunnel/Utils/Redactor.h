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

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Redactor implements a set of functions to redact sensitive values from data.
@interface Redactor : NSObject

/// Returns a redacted copy of the provided string where any file paths are replaced with "[redacted]". For example,
/// the input "prefix /a/b/c suffix" will result in the return value "prefix [redacted] suffix".
/// @warning An attempt is made to redact file paths, but there is no guarantee that all file path schemes on the
/// given system will be caught.
/// @param s The string to redact.
/// @return A copy of the provided string with any file paths redacted.
+ (NSString*)stripFilePaths:(NSString*)s;

/// Version of stripFilePaths which first replaces any occurrences of the provided file paths in the input string with
/// "[redacted]".
/// @warning An attempt is made to redact file paths, but there is no guarantee that all file path schemes on the given
/// system will be caught.
/// @param s The string to redact.
/// @param filePaths File paths to redact directly.
/// @return A copy of the provided string with any file paths redacted.
+ (NSString*)stripFilePaths:(NSString*)s withFilePaths:(NSArray<NSString*>*_Nullable)filePaths;

@end

NS_ASSUME_NONNULL_END
