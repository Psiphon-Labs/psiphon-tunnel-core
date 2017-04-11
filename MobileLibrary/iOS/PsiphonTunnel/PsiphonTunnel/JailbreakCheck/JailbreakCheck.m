// Adapted from https://github.com/olxios/JailbreakCheck
/*
 MIT License

 Copyright (c) 2016 olxios

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
*/


#import <Foundation/Foundation.h>
#import "UIKit/UIKit.h"
#import <sys/stat.h>
#import "JailbreakCheck.h"


@implementation JailbreakCheck


BOOL checkReadWritePermissions()
{
    // UIApplication:sharedApplication is disallowed in an application exetension
    // (such as would be used by a whole-device Psiphon VPN). We may re-enable
    // this code later, but leave it out for now to avoid confusion.
    /*
    if([[UIApplication sharedApplication] canOpenURL:
        [NSURL URLWithString:@"cydia://package/com.com.com"]])
    {
        return TRUE;
    }

    NSError *error;
    NSString *stringToBeWritten = @"0";
    [stringToBeWritten writeToFile:@"/private/jailbreak.test"
                        atomically:YES
                          encoding:NSUTF8StringEncoding error:&error];
    if (error == nil)
    {
        return TRUE;
    }
     */
    
    return FALSE;
}

BOOL checkJailbreakSymLink(NSString *checkPath)
{
    struct stat s;

    if (lstat([checkPath UTF8String], &s) == 0)
    {
        if (S_ISLNK(s.st_mode) == 1)
        {
            return TRUE;
        }
    }
    
    return FALSE;
}

BOOL checkJailbreakSymlinks()
{
    NSArray *linksChecks = @[@"/Applications",
                             @"/usr/libexec",
                             @"/usr/share",
                             @"/Library/Wallpaper",
                             @"/usr/include"];
    
    for (NSString *checkPath in linksChecks)
    {
        if (checkJailbreakSymLink(checkPath)) {
            return TRUE;
        }
    }
    
    return FALSE;
}

BOOL checkJailbreakFile(NSString *checkPath)
{
    struct stat s;

    if (stat([checkPath UTF8String], &s) == 0)
    {
        return TRUE;
    }
    
    return FALSE;
}

BOOL checkJailbreakFiles()
{
    NSArray *fileChecks = @[@"/bin/bash",
                            @"/etc/apt",
                            @"/usr/sbin/sshd",
                            @"/Library/MobileSubstrate/MobileSubstrate.dylib",
                            @"/Applications/Cydia.app",
                            @"/bin/sh",
                            @"/var/cache/apt",
                            @"/var/tmp/cydia.log"];
    
    for (NSString *checkPath in fileChecks)
    {
        if (checkJailbreakFile(checkPath)) {
            return TRUE;
        }
    }
    
    return FALSE;
}

+ (BOOL)isDeviceJailbroken
{
    return
        checkJailbreakSymlinks()
        || checkJailbreakFiles()
        || checkReadWritePermissions();
}

@end
