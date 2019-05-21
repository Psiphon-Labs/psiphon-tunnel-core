//
//  URLEncode.m
//  TunneledWebRequest
//
/*
 Licensed under Creative Commons Zero (CC0).
 https://creativecommons.org/publicdomain/zero/1.0/
 */


// NOTE: this file is shared by TunneledWebRequest and TunneledWebView

#import "URLEncode.h"

@implementation URLEncode

// Encode all reserved characters. See: https://stackoverflow.com/a/34788364.
//
// From RFC 3986 (https://www.ietf.org/rfc/rfc3986.txt):
//
//   2.3.  Unreserved Characters
//
//   Characters that are allowed in a URI but do not have a reserved
//   purpose are called unreserved.  These include uppercase and lowercase
//   letters, decimal digits, hyphen, period, underscore, and tilde.
//
//   unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
+ (NSString*)encode:(NSString*)url {
    NSCharacterSet *queryParamCharsAllowed = [NSCharacterSet
                                              characterSetWithCharactersInString:
                                              @"abcdefghijklmnopqrstuvwxyz"
                                              "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                              "0123456789"
                                              "-._~"];

    return [url stringByAddingPercentEncodingWithAllowedCharacters:queryParamCharsAllowed];
}

@end
