//
//  AuthURLSessionTaskDelegate.m
//  TunneledWebRequest
//
/*
 Licensed under Creative Commons Zero (CC0).
 https://creativecommons.org/publicdomain/zero/1.0/
 */


// NOTE: this file is shared by TunneledWebRequest and TunneledWebView

#import "AuthURLSessionTaskDelegate.h"

#import "OCSPCache.h"
#import "OCSPURLEncode.h"

@implementation AuthURLSessionTaskDelegate {
    OCSPCache *ocspCache;
}

-  (id)initWithLogger:(void (^)(NSString*))logger
andLocalHTTPProxyPort:(NSInteger)port {
    self = [super init];

    if (self) {
        self.logger = logger;
        self.localHTTPProxyPort = port;
        self->ocspCache = [[OCSPCache alloc] initWithLogger:^(NSString * _Nonnull logLine) {
            [self logWithFormat:@"[OCSPCache] %@", logLine];
        }];
    }

    return self;
}

- (void)logWithFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2) {
    if (self.logger != nil) {
        va_list arguments;
        
        va_start(arguments, format);
        NSString *message = [[NSString alloc] initWithFormat:format arguments:arguments];
        va_end(arguments);
        
        self.logger(message);
    }
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler
{
#pragma unused(session)
#pragma unused(task)
    assert(challenge != nil);
    assert(completionHandler != nil);
    
    // Resolve NSURLAuthenticationMethodServerTrust ourselves
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        [self logWithFormat:@"Got SSL certificate for %@, mainDocumentURL: %@, URL: %@",
         challenge.protectionSpace.host,
         [task.currentRequest mainDocumentURL],
         [task.currentRequest URL]];

        SecTrustRef trust = challenge.protectionSpace.serverTrust;
        if (trust == nil) {
            assert(NO);
        }

        SecPolicyRef policy = SecPolicyCreateRevocation(kSecRevocationOCSPMethod |
                                                        kSecRevocationRequirePositiveResponse |
                                                        kSecRevocationNetworkAccessDisabled);
        SecTrustSetPolicies(trust, policy);
        CFRelease(policy);

        // Check if there is a pinned or cached OCSP response

        SecTrustResultType trustResultType;
        SecTrustEvaluate(trust, &trustResultType);

        if (   trustResultType == kSecTrustResultProceed
            || trustResultType == kSecTrustResultUnspecified) {
            [self logWithFormat:@"Pinned or cached OCSP response found by the system"];
            NSURLCredential *credential = [NSURLCredential credentialForTrust:trust];
            assert(credential != nil);
            completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
            return;
        }

        // No pinned OCSP response, try fetching one

        [self logWithFormat:@"Fetching OCSP response through OCSPCache"];

        NSURL* (^modifyOCSPURL)(NSURL *url) = ^NSURL*(NSURL *url) {
            return [self modifyOCSPURL:url];
        };

        [ocspCache lookup:trust
               andTimeout:0
            modifyOCSPURL:modifyOCSPURL
               completion:
         ^(OCSPCacheLookupResult * _Nonnull result) {

             assert(result.response != nil);
             assert(result.err == nil);

             if (result.cached) {
                 [self logWithFormat:@"Got cached OCSP response from OCSPCache"];
             } else {
                 [self logWithFormat:@"Fetched OCSP response from remote"];
             }

             CFDataRef d = (__bridge CFDataRef)result.response.data;

             SecTrustSetOCSPResponse(trust, d);

             SecTrustResultType trustResultType;
             SecTrustEvaluate(trust, &trustResultType);

             if (   trustResultType == kSecTrustResultProceed
                 || trustResultType == kSecTrustResultUnspecified) {
                 NSURLCredential *credential = [NSURLCredential credentialForTrust:trust];
                 assert(credential != nil);
                 completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
                 return;
             }

             // Reject the protection space.
             // Do not use NSURLSessionAuthChallengePerformDefaultHandling because it can trigger
             // plaintext OCSP requests.
             completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
             return;
        }];

        return;
    }

    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

// Modify the OCSP URLs so they use the local HTTP proxy
- (nonnull NSURL *)modifyOCSPURL:(nonnull NSURL *)url {

    // The target URL must be encoded, so as to be valid within a query parameter.
    NSString *encodedTargetUrl = [URLEncode encode:url.absoluteString];

    NSNumber *httpProxyPort = [NSNumber numberWithInt:(int)self.localHTTPProxyPort];

    NSString *proxiedURLString = [NSString stringWithFormat:@"http://127.0.0.1:%@/tunneled/%@",
                                                            httpProxyPort,
                                                            encodedTargetUrl];
    NSURL *proxiedURL = [NSURL URLWithString:proxiedURLString];

    [self logWithFormat:@"[OCSPCache] updated OCSP URL %@ to %@", url, proxiedURL];

    return proxiedURL;
}

@end
