//
//  OCSP.h
//  TunneledWebRequest
//
/*
 Licensed under Creative Commons Zero (CC0).
 https://creativecommons.org/publicdomain/zero/1.0/
 */


// NOTE: this file is shared by TunneledWebRequest and TunneledWebView

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface OCSP : NSObject

/*
 * Check in SecTrustRef (X.509 cert) for Online Certificate Status Protocol (1.3.6.1.5.5.7.48.1)
 * authority information access method. This is found in the
 * Certificate Authority Information Access (1.3.6.1.5.5.7.1.1) X.509v3 extension.
 *
 * X.509 Authority Information Access: https://tools.ietf.org/html/rfc2459#section-4.2.2.1
 */
+ (NSArray<NSURL*>*_Nullable)ocspURLs:(SecTrustRef)secTrustRef error:(NSError**)error;

@end

NS_ASSUME_NONNULL_END
