//
//  PsiphonMobile.m
//  PsiphonMobile
//
//  Created by eugene-imac on 2016-08-16.
//  Copyright © 2016 Psiphon Inc. All rights reserved.
//

#import <Psi/Psi.h>
#import "PsiphonTunnelController.h"
#import "Reachability.h"

@interface PsiphonTunnelController () <GoPsiPsiphonProvider>
@end

@implementation PsiphonTunnelController


+(PsiphonTunnelController *) sharedInstance {
    static PsiphonTunnelController *sharedInstance = nil;
    static dispatch_once_t onceToken = 0;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
        // Do any other initialisation stuff here
    });
    return sharedInstance;
}

-(void) startTunnel {
    [self stopTunnel];
    [[self tunneledAppProtocolDelegate] onDiagnosticMessage:@"starting Psiphon library"];
    
    @try {
        NSString *configStr = [[self tunneledAppProtocolDelegate] getPsiphonConfig];
        NSError *e = nil;
        
        GoPsiStart(
                   configStr,
                   @"",
                   self,
                   false, // useDeviceBinder
                   &e);
    }
    @catch(NSException *exception) {
        [[self tunneledAppProtocolDelegate] onDiagnosticMessage:[NSString stringWithFormat: @"failed to start Psiphon library: %@", exception.reason]];
    }
    [[self tunneledAppProtocolDelegate] onDiagnosticMessage:@"Psiphon library started"];
}

-(void) stopTunnel {
    [[self tunneledAppProtocolDelegate] onDiagnosticMessage: @"stopping Psiphon library"];
    GoPsiStop();
    [[self tunneledAppProtocolDelegate] onDiagnosticMessage: @"Psiphon library stop"];
    
}

#pragma mark - GoPsiphonProvider protocol implementation

- (NSString*)getPrimaryDnsServer {
    return @"8.8.8.8";
}

- (NSString*)getSecondaryDnsServer {
    return @"8.8.4.4";    
}




- (BOOL)bindToDevice:(long)fileDescriptor error:(NSError**)error {
    return TRUE;
}

- (NSString*)getDnsServer {
    //This method is used only in VPN mode
    return @"";
}

- (long)hasNetworkConnectivity {
    Reachability *reachability = [Reachability reachabilityForInternetConnection];
    NetworkStatus netstat = [reachability currentReachabilityStatus];
    return (int) netstat != NotReachable;
}

- (void)notice:(NSString*)noticeJSON {
    NSData *noticeData = [noticeJSON dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error = nil;
    BOOL diagnostic = TRUE;
    
    NSDictionary *notice = [NSJSONSerialization JSONObjectWithData:noticeData options:kNilOptions error:&error];
    
    if(error) {
        
        // TODO: handle JSON error
        
    }
    else {
        NSString *noticeType = [notice valueForKey:@"noticeType"];
        if ([noticeType isEqualToString:@"Tunnels"]) {
            NSInteger count = [[[notice valueForKey: @"data"] valueForKey:@"count"] integerValue];
            if (count > 0) {
                [self.tunneledAppProtocolDelegate onConnected];
            } else {
                [self.tunneledAppProtocolDelegate onConnecting];
            }
            
        } else if ([noticeType isEqualToString:@"AvailableEgressRegions"]) {
            NSArray *regions = [[notice valueForKey: @"data"] valueForKey:@"regions"];
            [self.tunneledAppProtocolDelegate onAvailableEgressRegions:regions];
        } else if ([noticeType isEqualToString:@"SocksProxyPortInUse"]) {
            NSInteger port = [(NSNumber*)[[notice valueForKey: @"data"] valueForKey:@"port"] integerValue];
            [self.tunneledAppProtocolDelegate onSocksProxyPortInUse:port];
        } else if ([noticeType isEqualToString:@"HttpProxyPortInUse"]) {
            NSInteger port = [(NSNumber*)[[notice valueForKey: @"data"] valueForKey:@"port"] integerValue];
            [self.tunneledAppProtocolDelegate onHttpProxyPortInUse:port];
        } else if ([noticeType isEqualToString:@"ListeningSocksProxyPort"]) {
            NSInteger port = [(NSNumber*)[[notice valueForKey: @"data"] valueForKey:@"port"] integerValue];
            [self.tunneledAppProtocolDelegate onListeningSocksProxyPort:port];
        } else if ([noticeType isEqualToString:@"ListeningHttpProxyPort"]) {
            NSInteger port = [(NSNumber*)[[notice valueForKey: @"data"] valueForKey:@"port"] integerValue];
            [self.tunneledAppProtocolDelegate onListeningHttpProxyPort:port];
        } else if ([noticeType isEqualToString:@"UpstreamProxyError"]) {
            [self.tunneledAppProtocolDelegate onUpstreamProxyError:[[notice valueForKey: @"data"] valueForKey:@"message"]];
        } else if ([noticeType isEqualToString:@"ClientUpgradeDownloaded"]) {
            [self.tunneledAppProtocolDelegate onClientUpgradeDownloaded:[[notice valueForKey: @"data"] valueForKey:@"filename"]];
        } else if ([noticeType isEqualToString:@"Homepage"]) {
            [self.tunneledAppProtocolDelegate onHomepage:[[notice valueForKey: @"data"] valueForKey:@"url"]];
        } else if ([noticeType isEqualToString:@"ClientRegion"]) {
            [self.tunneledAppProtocolDelegate onClientRegion:[[notice valueForKey: @"data"] valueForKey:@"region"]];
        } else if ([noticeType isEqualToString:@"UntunneledAddress"]) {
            [self.tunneledAppProtocolDelegate onUntunneledAddress :[[notice valueForKey: @"data"] valueForKey:@"address"]];
        } else if ([noticeType isEqualToString:@"BytesTransferred"]) {
            diagnostic = FALSE;
            NSDictionary *bytes = [notice valueForKey: @"data"];
            [self.tunneledAppProtocolDelegate onBytesTransferred:[bytes[@"received"] longValue]:[bytes[@"sent"] longValue]];
        }
        
        if (diagnostic) {
            NSData *diagnosticData = [NSJSONSerialization dataWithJSONObject:[notice valueForKey: @"data"] options:kNilOptions error:&error];
            if (error == nil){
                NSString *diagnosticStr = [[NSString alloc] initWithData:diagnosticData encoding:NSUTF8StringEncoding];
                NSString *diagnosticMessage = [NSString stringWithFormat:@"%@: %@", noticeType, diagnosticStr];
                [self. tunneledAppProtocolDelegate onDiagnosticMessage : diagnosticMessage];
            }
        }
    }
}

@end

@implementation Psi
+ (void)sendFeedback:(NSString*)configJson diagnostics: (NSString*)diagnosticsJson b64EncodedPublicKey: (NSString*) b64EncodedPublicKey uploadServer: (NSString*)uploadServer uploadPath: (NSString*) uploadPath uploadServerHeaders: (NSString*)uploadServerHeaders {
    GoPsiSendFeedback(configJson, diagnosticsJson, b64EncodedPublicKey, uploadServer, uploadPath, uploadServerHeaders);
}
@end
