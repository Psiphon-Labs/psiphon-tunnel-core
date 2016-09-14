//
//  PsiphonMobile.h
//  PsiphonMobile
//
//  Created by eugene-imac on 2016-08-16.
//  Copyright © 2016 Psiphon Inc. All rights reserved.
//


//! Project version number for PsiphonMobile.
FOUNDATION_EXPORT double PsiphonMobileVersionNumber;

//! Project version string for PsiphonMobile.
FOUNDATION_EXPORT const unsigned char PsiphonMobileVersionString[];

// In this header, you should import all the public headers of your framework using statements like #import <PsiphonMobile/PublicHeader.h>


@protocol TunneledAppProtocol
- (NSString *) getPsiphonConfig;
- (void) onDiagnosticMessage: (NSString *) message;
- (void) onAvailableEgressRegions: (NSArray *) regions;
- (void) onSocksProxyPortInUse: (NSInteger) port;
- (void) onHttpProxyPortInUse: (NSInteger) port;
- (void) onListeningSocksProxyPort: (NSInteger) port;
- (void) onListeningHttpProxyPort: (NSInteger) port;
- (void) onUpstreamProxyError: (NSString *) message;
- (void) onConnecting;
- (void) onConnected;
- (void) onHomepage: (NSString *) url;
- (void) onClientRegion: (NSString *) region;
- (void) onClientUpgradeDownloaded: (NSString *) filename;
- (void) onSplitTunnelRegion: (NSString *) region;
- (void) onUntunneledAddress: (NSString *) address;
- (void) onBytesTransferred: (long) sent : (long) received;
- (void) onStartedWaitingForNetworkConnectivity;
@end


@interface PsiphonTunnelController : NSObject

@property (weak) id <TunneledAppProtocol> tunneledAppProtocolDelegate;
@property (nonatomic) NSInteger listeningSocksProxyPort;
@property (nonatomic) NSArray *homepages;


+ (id) sharedInstance;

-(void) startTunnel;
-(void) stopTunnel;

@end

@interface Psi : NSObject
+ (void)sendFeedback:(NSString*)configJson diagnostics: (NSString*)diagnosticsJson b64EncodedPublicKey: (NSString*) b64EncodedPublicKey uploadServer: (NSString*)uploadServer uploadPath: (NSString*) uploadPath uploadServerHeaders: (NSString*)uploadServerHeaders;
@end
