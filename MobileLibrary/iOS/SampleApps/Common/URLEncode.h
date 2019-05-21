//
//  URLEncode.h
//  TunneledWebRequest
//
/*
 Licensed under Creative Commons Zero (CC0).
 https://creativecommons.org/publicdomain/zero/1.0/
 */


// NOTE: this file is shared by TunneledWebRequest and TunneledWebView

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface URLEncode : NSObject

// See comment in URLEncode.m
+ (NSString*__nullable)encode:(NSString*)url;

@end

NS_ASSUME_NONNULL_END
