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

#import "OCSP.h"
#import "URLEncode.h"

@implementation AuthURLSessionTaskDelegate

- (id)initWithLogger:(void (^)(NSString*))logger andLocalHTTPProxyPort:(NSInteger)port{
    self = [super init];

    if (self) {
        self.logger = logger;
        self.localHTTPProxyPort = port;
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
        
        NSError *e;
        
        NSArray <NSURL*>* ocspURLs = [OCSP ocspURLs:trust error:&e];
        if (e != nil) {
            [self logWithFormat:@"Error constructing OCSP URLs: %@", e.localizedDescription];
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
            return;
        }
        
        if ([ocspURLs count] == 0) {
            [self logWithFormat:
             @"Error no OCSP URLs in the Certificate Authority Information Access "
             "(1.3.6.1.5.5.7.1.1) extension."];
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
            return;
        }
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
            for (NSURL *ocspURL in ocspURLs) {
                
                // The target URL must be encoded, so as to be valid within a query parameter.
                NSString *encodedTargetUrl = [URLEncode encode:ocspURL.absoluteString];
                
                NSNumber *httpProxyPort = [NSNumber numberWithInt:
                                           (int)self.localHTTPProxyPort];
                
                NSString *proxiedURLString = [NSString stringWithFormat:@"http://127.0.0.1:%@"
                                              "/tunneled/%@",
                                              httpProxyPort,
                                              encodedTargetUrl];
                NSURL *proxiedURL = [NSURL URLWithString:proxiedURLString];
                if (proxiedURL == nil) {
                    [self logWithFormat:@"Constructed invalid URL for OCSP request: %@",
                                        proxiedURLString];
                    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
                    return;
                }
                
                NSURLRequest *ocspReq = [NSURLRequest requestWithURL:proxiedURL];

                NSURLResponse *resp = nil;
                NSError *e = nil;
                NSData *data = [NSURLConnection sendSynchronousRequest:ocspReq
                                                     returningResponse:&resp
                                                                 error:&e];
                if (e != nil) {
                    [self logWithFormat:@"Error with OCSP request: %@", e.localizedDescription];
                    continue;
                }
                
                CFDataRef d = (__bridge CFDataRef)data;
                SecTrustSetOCSPResponse(trust, d);
                
                SecTrustResultType trustResultType;
                SecTrustEvaluate(trust, &trustResultType);

                if (trustResultType == kSecTrustResultProceed || trustResultType == kSecTrustResultUnspecified) {
                    NSURLCredential *credential = [NSURLCredential credentialForTrust:
                                                   challenge.protectionSpace.serverTrust];
                    assert(credential != nil);
                    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
                    return;
                }

                completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
                return;
            }
        });

        return;
    }

    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

@end
