//
//  AuthURLSessionTaskDelegate.h
//  TunneledWebRequest
//
/*
 Licensed under Creative Commons Zero (CC0).
 https://creativecommons.org/publicdomain/zero/1.0/
 */


// NOTE: this file is shared by TunneledWebRequest and TunneledWebView

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/*
 * AuthURLSessionTaskDelegate implements URLSession:task:didReceiveChallenge:completionHandler:
 * of the NSURLSessionTaskDelegate protocol.
 *
 * The main motivation of AuthURLSessionTaskDelegate is to ensure that OCSP requests are not
 * sent in plaintext outside of the tunnel.
 *
 * If the policy object for checking the revocation of certificates is created with
 * SecPolicyCreateRevocation(kSecRevocationOCSPMethod | ...), and network access is allowed
 * (the kSecRevocationNetworkAccessDisabled flag is not provided), a plaintext OCSP request over
 * HTTP is triggered when SecTrustEvaluate() is called. This request does not respect NSURLProtocol
 * subclassing.
 *
 * The solution is to inspect each X.509 certificate for the Online Certificate Status Protocol
 * (1.3.6.1.5.5.7.48.1) Authority Information Access Method, which contains the locations (URLs) of
 * the OCSP servers; then OCSP requests are then made to these servers through the local HTTP proxy.
 *
 * Note: The OCSP Authority Information Access Method is found in the Certificate Authority
 *       Information Access (1.3.6.1.5.5.7.1.1) X.509v3 extension --
 *       https://tools.ietf.org/html/rfc2459#section-4.2.2.1.
 */
@interface AuthURLSessionTaskDelegate : NSObject <NSURLSessionDelegate>

/*
 * Logger for errors.
 */
@property (nonatomic, strong) void (^logger)(NSString*);

/*
 * Local HTTP proxy port.
 *
 * OCSP request URL is constructed as:
 *   http://127.0.0.1:<HTTP proxy port>/tunneled/<URL encoded OCSP request>
 */
@property (atomic, assign) NSInteger localHTTPProxyPort;

- (id)initWithLogger:(void (^)(NSString*))logger andLocalHTTPProxyPort:(NSInteger)port;

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler;

@end

NS_ASSUME_NONNULL_END
