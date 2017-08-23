/*
 * Copyright (c) 2016, Psiphon Inc.
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

#import <arpa/inet.h>
#import <net/if.h>
#import <stdatomic.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import "LookupIPv6.h"
#import "Psi-meta.h"
#import "PsiphonTunnel.h"
#import "json-framework/SBJson4.h"
#import "JailbreakCheck/JailbreakCheck.h"
#include <ifaddrs.h>


@interface PsiphonTunnel () <GoPsiPsiphonProvider>

@property (weak) id <TunneledAppDelegate> tunneledAppDelegate;

@end

@implementation PsiphonTunnel {
    dispatch_queue_t workQueue;
    dispatch_queue_t callbackQueue;
    dispatch_semaphore_t noticeHandlingSemaphore;

    _Atomic PsiphonConnectionState connectionState;

    _Atomic NSInteger localSocksProxyPort;
    _Atomic NSInteger localHttpProxyPort;

    Reachability* reachability;
    NetworkStatus previousNetworkStatus;

    BOOL tunnelWholeDevice;
}

- (id)init {
    self.tunneledAppDelegate = nil;

    self->workQueue = dispatch_queue_create("com.psiphon3.library.WorkQueue", DISPATCH_QUEUE_SERIAL);
    self->callbackQueue = dispatch_queue_create("com.psiphon3.library.CallbackQueue", DISPATCH_QUEUE_SERIAL);
    self->noticeHandlingSemaphore = dispatch_semaphore_create(1);

    atomic_init(&self->connectionState, PsiphonConnectionStateDisconnected);
    atomic_init(&self->localSocksProxyPort, 0);
    atomic_init(&self->localHttpProxyPort, 0);
    self->reachability = [Reachability reachabilityForInternetConnection];
    self->tunnelWholeDevice = FALSE;

    return self;
}

#pragma mark - PsiphonTunnel public methods

// See comment in header
+ (PsiphonTunnel * _Nonnull)newPsiphonTunnel:(id<TunneledAppDelegate> _Nonnull)tunneledAppDelegate {
    @synchronized (PsiphonTunnel.self) {
        // Only one PsiphonTunnel instance may exist at a time, as the underlying
        // go.psi.Psi and tun2socks implementations each contain global state.
        
        static PsiphonTunnel *sharedInstance = nil;
        static dispatch_once_t onceToken = 0;
        dispatch_once(&onceToken, ^{
            sharedInstance = [[self alloc] init];
        });

        [sharedInstance stop];
        sharedInstance.tunneledAppDelegate = tunneledAppDelegate;

        return sharedInstance;
    }
}

// See comment in header
- (BOOL)start:(BOOL)ifNeeded {
    if (ifNeeded) {
        return [self startIfNeeded];
    }

    return [self start];
}

/*!
 Start the tunnel. If the tunnel is already started it will be stopped first.
 */
- (BOOL)start {
    @synchronized (PsiphonTunnel.self) {
        [self stop];
        [self logMessage:@"Starting Psiphon library"];

        // Must always use IPv6Synthesizer for iOS
        const BOOL useIPv6Synthesizer = TRUE;
        
        NSString *configStr = [self getConfig];
        if (configStr == nil) {
            [self logMessage:@"Error getting config from delegate"];
            return FALSE;
        }

        __block NSString *embeddedServerEntriesPath = nil;
        __block NSString *embeddedServerEntries = nil;
        
        dispatch_sync(self->callbackQueue, ^{
            embeddedServerEntriesPath = [self.tunneledAppDelegate getEmbeddedServerEntriesPath];
        });
        
        // If getEmbeddedServerEntriesPath returns nil or empty string,
        // call getEmbeddedServerEntries
        if (embeddedServerEntriesPath == nil || [embeddedServerEntriesPath length] == 0) {
            
            dispatch_sync(self->callbackQueue, ^{
                embeddedServerEntries = [self.tunneledAppDelegate getEmbeddedServerEntries];
            });
            
            if (embeddedServerEntries == nil) {
                [self logMessage:@"Error getting embedded server entries from delegate"];
                return FALSE;
            }
        }

        [self changeConnectionStateTo:PsiphonConnectionStateConnecting evenIfSameState:NO];

        @try {
            NSError *e = nil;

            BOOL res = GoPsiStart(
                           configStr,
                           embeddedServerEntries,
                           embeddedServerEntriesPath,
                           self,
                           self->tunnelWholeDevice, // useDeviceBinder
                           useIPv6Synthesizer,
                           &e);
            
            [self logMessage:[NSString stringWithFormat: @"GoPsiStart: %@", res ? @"TRUE" : @"FALSE"]];
            
            if (e != nil) {
                [self logMessage:[NSString stringWithFormat: @"Psiphon tunnel start failed: %@", e.localizedDescription]];
                [self changeConnectionStateTo:PsiphonConnectionStateDisconnected evenIfSameState:NO];
                return FALSE;
            }
        }
        @catch(NSException *exception) {
            [self logMessage:[NSString stringWithFormat: @"Failed to start Psiphon library: %@", exception.reason]];
            [self changeConnectionStateTo:PsiphonConnectionStateDisconnected evenIfSameState:NO];
            return FALSE;
        }

        [self startInternetReachabilityMonitoring];

        [self logMessage:@"Psiphon tunnel started"];
        
        return TRUE;
    }
}

/*!
 Start the tunnel if it's not already started.
 */
- (BOOL)startIfNeeded {
    PsiphonConnectionState connState = [self getConnectionState];
    BOOL localProxyAlive = [self isLocalProxyAlive];

    // We have found that on iOS, the local proxies will get killed before the
    // tunnel gets disconnected (or before it realizes it's dead). So we need to
    // start if we either in a disconnected state or if our local proxies are dead.
    if ((connState == PsiphonConnectionStateDisconnected) ||
        (connState == PsiphonConnectionStateConnected && !localProxyAlive)) {
        return [self start];
    }

    // Otherwise we're already connected, so let the app know via the same signaling
    // that we'd use if we were doing a connection sequence.
    [self changeConnectionStateTo:connState evenIfSameState:YES];

    return TRUE;
}

// See comment in header.
- (void)stop {
    @synchronized (PsiphonTunnel.self) {
        [self logMessage: @"Stopping Psiphon library"];

        [self stopInternetReachabilityMonitoring];

        GoPsiStop();
        
        [self logMessage: @"Psiphon library stopped"];

        atomic_store(&self->localSocksProxyPort, 0);
        atomic_store(&self->localHttpProxyPort, 0);

        [self changeConnectionStateTo:PsiphonConnectionStateDisconnected evenIfSameState:NO];
    }
}

// See comment in header.
- (PsiphonConnectionState)getConnectionState {
    return atomic_load(&self->connectionState);
}

// See comment in header.
- (NSInteger)getLocalSocksProxyPort {
    return atomic_load(&self->localSocksProxyPort);
}

// See comment in header.
- (NSInteger)getLocalHttpProxyPort {
    return atomic_load(&self->localHttpProxyPort);
}

// See comment in header.
- (long)getPacketTunnelMTU {
    return GoPsiGetPacketTunnelMTU();
}

// See comment in header.
- (NSString * _Nonnull)getPacketTunnelDNSResolverIPv4Address {
    return GoPsiGetPacketTunnelDNSResolverIPv4Address();
}

// See comment in header.
- (NSString * _Nonnull)getPacketTunnelDNSResolverIPv6Address {
    return GoPsiGetPacketTunnelDNSResolverIPv6Address();
}

// See comment in header.
- (void)sendFeedback:(NSString * _Nonnull)feedbackJson
           publicKey:(NSString * _Nonnull)b64EncodedPublicKey
        uploadServer:(NSString * _Nonnull)uploadServer
 uploadServerHeaders:(NSString * _Nonnull)uploadServerHeaders {
    dispatch_async(self->workQueue, ^{
        NSString *connectionConfigJson = [self getConfig];
        if (connectionConfigJson == nil) {
           [self logMessage:@"Error getting config for feedback upload"];
        }

        GoPsiSendFeedback(connectionConfigJson, feedbackJson, b64EncodedPublicKey, uploadServer, @"", uploadServerHeaders);
    });
}


#pragma mark - PsiphonTunnel logic implementation methods (private)

/*!
 Build the config string for the tunnel.
 @returns String containing the JSON config. `nil` on error.
 */
- (NSString * _Nullable)getConfig {
    // tunneledAppDelegate is a weak reference, so check it.
    if (self.tunneledAppDelegate == nil) {
        [self logMessage:@"tunneledApp delegate lost"];
        return nil;
    }

    __block NSString *configStr = nil;
    dispatch_sync(self->callbackQueue, ^{
        configStr = [self.tunneledAppDelegate getPsiphonConfig];
    });
    if (configStr == nil) {
        [self logMessage:@"Error getting config from delegate"];
        return nil;
    }
    
    __block NSDictionary *initialConfig = nil;
    id block = ^(id obj, BOOL *ignored) {
        if (ignored == nil || *ignored == YES) {
            return;
        }
        initialConfig = (NSDictionary *)obj;
    };
    
    id eh = ^(NSError *err) {
        initialConfig = nil;
        [self logMessage:[NSString stringWithFormat: @"Config JSON parse failed: %@", err.description]];
    };
    
    id parser = [SBJson4Parser parserWithBlock:block allowMultiRoot:NO unwrapRootArray:NO errorHandler:eh];
    [parser parse:[configStr dataUsingEncoding:NSUTF8StringEncoding]];
    
    if (initialConfig == nil) {
        return nil;
    }
    
    NSMutableDictionary *config = [NSMutableDictionary dictionaryWithDictionary:initialConfig];
    
    //
    // Check for required values
    //
    
    if (config[@"PropagationChannelId"] == nil) {
        [self logMessage:@"Config missing PropagationChannelId"];
        return nil;
    }

    if (config[@"SponsorId"] == nil) {
        [self logMessage:@"Config missing SponsorId"];
        return nil;
    }
    
    //
    // Fill in optional config values.
    //

    if (config[@"EstablishTunnelTimeoutSeconds"] == nil) {
        // If not otherwise set, we want no tunnel establishment timeout
        config[@"EstablishTunnelTimeoutSeconds"] = [NSNumber numberWithInt:0];
    }

    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    NSError* err = nil;
    NSURL *libraryURL = [fileManager URLForDirectory:NSLibraryDirectory inDomain:NSUserDomainMask appropriateForURL:nil create:YES error:&err];
    
    if (libraryURL == nil) {
        [self logMessage:[NSString stringWithFormat: @"Unable to get Library URL: %@", err.localizedDescription]];
        return nil;
    }
    
    //
    // DataStoreDirectory
    //
    
    // Some clients will have a data directory that they'd prefer the Psiphon
    // library use, but if not we'll default to the user Library directory.
    NSURL *defaultDataStoreDirectoryURL = [libraryURL URLByAppendingPathComponent:@"datastore" isDirectory:YES];
    
    if (defaultDataStoreDirectoryURL == nil) {
        [self logMessage:@"Unable to create defaultDataStoreDirectoryURL"];
        return nil;
    }
    
    if (config[@"DataStoreDirectory"] == nil) {
        [fileManager createDirectoryAtURL:defaultDataStoreDirectoryURL withIntermediateDirectories:YES attributes:nil error:&err];
        if (err != nil) {
            [self logMessage:[NSString stringWithFormat: @"Unable to create defaultDataStoreDirectoryURL: %@", err.localizedDescription]];
            return nil;
        }
        
        config[@"DataStoreDirectory"] = [defaultDataStoreDirectoryURL path];
    }
    else {
        [self logMessage:[NSString stringWithFormat: @"DataStoreDirectory overridden from '%@' to '%@'", [defaultDataStoreDirectoryURL path], config[@"DataStoreDirectory"]]];
    }
    
    //
    // Remote Server List
    //
    
    NSString *defaultRemoteServerListFilename = [[libraryURL URLByAppendingPathComponent:@"remote_server_list" isDirectory:NO] path];
    if (defaultRemoteServerListFilename == nil) {
        [self logMessage:@"Unable to create defaultRemoteServerListFilename"];
        return nil;
    }
    
    if (config[@"RemoteServerListDownloadFilename"] == nil) {
        config[@"RemoteServerListDownloadFilename"] = defaultRemoteServerListFilename;
    }
    else {
        [self logMessage:[NSString stringWithFormat: @"RemoteServerListDownloadFilename overridden from '%@' to '%@'", defaultRemoteServerListFilename, config[@"RemoteServerListDownloadFilename"]]];
    }
    
    // If RemoteServerListUrl/RemoteServerListURLs and RemoteServerListSignaturePublicKey
    // are absent, we'll just leave them out, but we'll log about it.
    if ((config[@"RemoteServerListUrl"] == nil && config[@"RemoteServerListURLs"] == nil) ||
        config[@"RemoteServerListSignaturePublicKey"] == nil) {
        [self logMessage:@"Remote server list functionality will be disabled"];
    }
    
    //
    // Obfuscated Server List
    //
    
    NSURL *defaultOSLDirectoryURL = [libraryURL URLByAppendingPathComponent:@"osl" isDirectory:YES];
    if (defaultOSLDirectoryURL == nil) {
        [self logMessage:@"Unable to create defaultOSLDirectory"];
        return nil;
    }
    
    if (config[@"ObfuscatedServerListDownloadDirectory"] == nil) {
        [fileManager createDirectoryAtURL:defaultOSLDirectoryURL withIntermediateDirectories:YES attributes:nil error:&err];
        if (err != nil) {
            [self logMessage:[NSString stringWithFormat: @"Unable to create defaultOSLDirectoryURL: %@", err.localizedDescription]];
            return nil;
        }
        
        config[@"ObfuscatedServerListDownloadDirectory"] = [defaultOSLDirectoryURL path];
    }
    else {
        [self logMessage:[NSString stringWithFormat: @"ObfuscatedServerListDownloadDirectory overridden from '%@' to '%@'", [defaultOSLDirectoryURL path], config[@"ObfuscatedServerListDownloadDirectory"]]];
    }
    
    // If ObfuscatedServerListRootURL/ObfuscatedServerListRootURLs is absent,
    // we'll leave it out, but log the absence.
    if (config[@"ObfuscatedServerListRootURL"] == nil && config[@"ObfuscatedServerListRootURLs"] == nil) {
        [self logMessage:@"Obfuscated server list functionality will be disabled"];
    }

    //
    // Tunnel Whole Device (defaults to not whole device)
    //

    // We'll record our state about what mode we're in.
    self->tunnelWholeDevice = ([config[@"TunnelWholeDevice"] integerValue] == 1);

    // Other optional fields not being altered. If not set, their defaults will be used:
    // * TunnelWholeDevice
    // * LocalSocksProxyPort
    // * LocalHttpProxyPort
    // * UpstreamProxyUrl
    // * EmitDiagnosticNotices
    // * EgressRegion
    // * timeout fields
    
    //
    // Fill in the rest of the values.
    //
    
    // ClientPlatform must not contain:
    //   - underscores, which are used by us to separate the constituent parts
    //   - spaces, which are considered invalid by the server
    // Like "iOS". Older iOS reports "iPhone OS", which we will convert.
    NSString *systemName = [[UIDevice currentDevice] systemName];
    if ([systemName isEqual: @"iPhone OS"]) {
        systemName = @"iOS";
    }
    systemName = [[systemName
                   stringByReplacingOccurrencesOfString:@"_" withString:@"-"]
                  stringByReplacingOccurrencesOfString:@" " withString:@"-"];
    // Like "10.2.1"
    NSString *systemVersion = [[[[UIDevice currentDevice]systemVersion]
                                stringByReplacingOccurrencesOfString:@"_" withString:@"-"]
                               stringByReplacingOccurrencesOfString:@" " withString:@"-"];
    
    // "unjailbroken"/"jailbroken"
    NSString *jailbroken = @"unjailbroken";
    if ([JailbreakCheck isDeviceJailbroken]) {
        jailbroken = @"jailbroken";
    }
    // Like "com.psiphon3.browser"
    NSString *bundleIdentifier = [[[[NSBundle mainBundle] bundleIdentifier]
                                   stringByReplacingOccurrencesOfString:@"_" withString:@"-"]
                                  stringByReplacingOccurrencesOfString:@" " withString:@"-"];
    
    NSString *clientPlatform = [NSString stringWithFormat:@"%@_%@_%@_%@",
                                systemName,
                                systemVersion,
                                jailbroken,
                                bundleIdentifier];
    
    config[@"ClientPlatform"] = clientPlatform;
        
    config[@"EmitBytesTransferred"] = [NSNumber numberWithBool:TRUE];

    config[@"DeviceRegion"] = [PsiphonTunnel getDeviceRegion];
    
    config[@"UseIndistinguishableTLS"] = [NSNumber numberWithBool:TRUE];

    // We don't use OpenSSL, so we don't use a CA certs file
    config[@"TrustedCACertificatesFilename"] = nil;

    // This library expects a pool size of 1
    config[@"TunnelPoolSize"] = [NSNumber numberWithInt:1];

    // We don't support upgrade downloading
    config[@"UpgradeDownloadURLs"] = nil;
    config[@"UpgradeDownloadUrl"] = nil;
    config[@"UpgradeDownloadClientVersionHeader"] = nil;
    config[@"UpgradeDownloadFilename"] = nil;

    NSString *finalConfigStr = [[[SBJson4Writer alloc] init] stringWithObject:config];
    
    if (finalConfigStr == nil) {
        [self logMessage:@"Failed to convert config to JSON string"];
        return nil;
    }

    return finalConfigStr;
}

/*!
 Process notices from tunnel core.
 @param noticeJSON  The notice data, JSON encoded.
 */
- (void)handlePsiphonNotice:(NSString * _Nonnull)noticeJSON {
    BOOL diagnostic = TRUE;
    
    __block NSDictionary *notice = nil;
    id block = ^(id obj, BOOL *ignored) {
        if (ignored == nil || *ignored == YES) {
            return;
        }
        notice = (NSDictionary *)obj;
    };
    
    id eh = ^(NSError *err) {
        notice = nil;
        [self logMessage:[NSString stringWithFormat: @"Notice JSON parse failed: %@", err.description]];
    };
    
    id parser = [SBJson4Parser parserWithBlock:block allowMultiRoot:NO unwrapRootArray:NO errorHandler:eh];
    [parser parse:[noticeJSON dataUsingEncoding:NSUTF8StringEncoding]];
    
    if (notice == nil) {
        return;
    }

    NSString *noticeType = notice[@"noticeType"];
    if (noticeType == nil) {
        [self logMessage:@"Notice missing noticeType"];
        return;
    }
    
    if ([noticeType isEqualToString:@"Tunnels"]) {
        id count = [notice valueForKeyPath:@"data.count"];
        if (![count isKindOfClass:[NSNumber class]]) {
            [self logMessage:[NSString stringWithFormat: @"Tunnels notice missing data.count: %@", noticeJSON]];
            return;
        }

        if ([count integerValue] > 0) {
            [self changeConnectionStateTo:PsiphonConnectionStateConnected evenIfSameState:NO];
        } else {
            [self changeConnectionStateTo:PsiphonConnectionStateConnecting evenIfSameState:NO];
        }
    }
    else if ([noticeType isEqualToString:@"Exiting"]) {
        if ([self.tunneledAppDelegate respondsToSelector:@selector(onExiting)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onExiting];
            });
        }
    }
    else if ([noticeType isEqualToString:@"AvailableEgressRegions"]) {
        id regions = [notice valueForKeyPath:@"data.regions"];
        if (![regions isKindOfClass:[NSArray class]]) {
            [self logMessage:[NSString stringWithFormat: @"AvailableEgressRegions notice missing data.regions: %@", noticeJSON]];
            return;
        }

        if ([self.tunneledAppDelegate respondsToSelector:@selector(onAvailableEgressRegions:)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onAvailableEgressRegions:regions];
            });
        }
    }
    else if ([noticeType isEqualToString:@"SocksProxyPortInUse"]) {
        id port = [notice valueForKeyPath:@"data.port"];
        if (![port isKindOfClass:[NSNumber class]]) {
            [self logMessage:[NSString stringWithFormat: @"SocksProxyPortInUse notice missing data.port: %@", noticeJSON]];
            return;
        }

        if ([self.tunneledAppDelegate respondsToSelector:@selector(onSocksProxyPortInUse:)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onSocksProxyPortInUse:[port integerValue]];
            });
        }
    }
    else if ([noticeType isEqualToString:@"HttpProxyPortInUse"]) {
        id port = [notice valueForKeyPath:@"data.port"];
        if (![port isKindOfClass:[NSNumber class]]) {
            [self logMessage:[NSString stringWithFormat: @"HttpProxyPortInUse notice missing data.port: %@", noticeJSON]];
            return;
        }

        if ([self.tunneledAppDelegate respondsToSelector:@selector(onHttpProxyPortInUse:)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onHttpProxyPortInUse:[port integerValue]];
            });
        }
    }
    else if ([noticeType isEqualToString:@"ListeningSocksProxyPort"]) {
        id port = [notice valueForKeyPath:@"data.port"];
        if (![port isKindOfClass:[NSNumber class]]) {
            [self logMessage:[NSString stringWithFormat: @"ListeningSocksProxyPort notice missing data.port: %@", noticeJSON]];
            return;
        }

        NSInteger portInt = [port integerValue];

        atomic_store(&self->localSocksProxyPort, portInt);

        if ([self.tunneledAppDelegate respondsToSelector:@selector(onListeningSocksProxyPort:)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onListeningSocksProxyPort:portInt];
            });
        }
    }
    else if ([noticeType isEqualToString:@"ListeningHttpProxyPort"]) {
        id port = [notice valueForKeyPath:@"data.port"];
        if (![port isKindOfClass:[NSNumber class]]) {
            [self logMessage:[NSString stringWithFormat: @"ListeningHttpProxyPort notice missing data.port: %@", noticeJSON]];
            return;
        }

        NSInteger portInt = [port integerValue];

        atomic_store(&self->localHttpProxyPort, portInt);

        if ([self.tunneledAppDelegate respondsToSelector:@selector(onListeningHttpProxyPort:)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onListeningHttpProxyPort:portInt];
            });
        }
    }
    else if ([noticeType isEqualToString:@"UpstreamProxyError"]) {
        id message = [notice valueForKeyPath:@"data.message"];
        if (![message isKindOfClass:[NSString class]]) {
            [self logMessage:[NSString stringWithFormat: @"UpstreamProxyError notice missing data.message: %@", noticeJSON]];
            return;
        }
        
        if ([self.tunneledAppDelegate respondsToSelector:@selector(onUpstreamProxyError:)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onUpstreamProxyError:message];
            });
        }
    }
    else if ([noticeType isEqualToString:@"ClientUpgradeDownloaded"]) {
        // We don't support upgrade downloading
    }
    else if ([noticeType isEqualToString:@"ClientIsLatestVersion"]) {
        // We don't support upgrade downloading
    }
    else if ([noticeType isEqualToString:@"Homepage"]) {
        id url = [notice valueForKeyPath:@"data.url"];
        if (![url isKindOfClass:[NSString class]]) {
            [self logMessage:[NSString stringWithFormat: @"Homepage notice missing data.url: %@", noticeJSON]];
            return;
        }
        
        if ([self.tunneledAppDelegate respondsToSelector:@selector(onHomepage:)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onHomepage:url];
            });
        }
    }
    else if ([noticeType isEqualToString:@"ClientRegion"]) {
        id region = [notice valueForKeyPath:@"data.region"];
        if (![region isKindOfClass:[NSString class]]) {
            [self logMessage:[NSString stringWithFormat: @"ClientRegion notice missing data.region: %@", noticeJSON]];
            return;
        }
        
        if ([self.tunneledAppDelegate respondsToSelector:@selector(onClientRegion:)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onClientRegion:region];
            });
        }
    }
    else if ([noticeType isEqualToString:@"SplitTunnelRegion"]) {
        id region = [notice valueForKeyPath:@"data.region"];
        if (![region isKindOfClass:[NSString class]]) {
            [self logMessage:[NSString stringWithFormat: @"SplitTunnelRegion notice missing data.region: %@", noticeJSON]];
            return;
        }
        
        if ([self.tunneledAppDelegate respondsToSelector:@selector(onSplitTunnelRegion:)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onSplitTunnelRegion:region];
            });
        }
    }
    else if ([noticeType isEqualToString:@"Untunneled"]) {
        id address = [notice valueForKeyPath:@"data.address"];
        if (![address isKindOfClass:[NSString class]]) {
            [self logMessage:[NSString stringWithFormat: @"Untunneled notice missing data.address: %@", noticeJSON]];
            return;
        }
        
        if ([self.tunneledAppDelegate respondsToSelector:@selector(onUntunneledAddress:)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onUntunneledAddress:address];
            });
        }
    }
    else if ([noticeType isEqualToString:@"BytesTransferred"]) {
        diagnostic = FALSE;
        
        id sent = [notice valueForKeyPath:@"data.sent"];
        id received = [notice valueForKeyPath:@"data.received"];
        if (![sent isKindOfClass:[NSNumber class]] || ![received isKindOfClass:[NSNumber class]]) {
            [self logMessage:[NSString stringWithFormat: @"BytesTransferred notice missing data.sent or data.received: %@", noticeJSON]];
            return;
        }
        
        if ([self.tunneledAppDelegate respondsToSelector:@selector(onBytesTransferred::)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onBytesTransferred:[sent longLongValue]:[received longLongValue]];
            });
        }
    }
    
    // Pass diagnostic messages to onDiagnosticMessage.
    if (diagnostic) {
        NSDictionary *data = notice[@"data"];
        if (data == nil) {
            return;
        }
        
        NSString *dataStr = [[[SBJson4Writer alloc] init] stringWithObject:data];

        NSString *diagnosticMessage = [NSString stringWithFormat:@"%@: %@", noticeType, dataStr];
        [self logMessage:diagnosticMessage];
    }
}


#pragma mark - GoPsiPsiphonProvider protocol implementation (private)

- (BOOL)bindToDevice:(long)fileDescriptor error:(NSError **)error {
    if (!self->tunnelWholeDevice) {
        return FALSE;
    }
    
    NSString *activeInterface = [self getActiveInterface];
    if (activeInterface == nil) {
        return FALSE;
    }
    [self logMessage:[NSString stringWithFormat:@"bindToDevice: Active interface: %@", activeInterface]];
    
    unsigned int interfaceIndex = if_nametoindex([activeInterface UTF8String]);
    if (interfaceIndex == 0) {
        // if_nametoindex returns 0 on error.
        [self logMessage:[NSString stringWithFormat:@"bindToDevice: if_nametoindex error for interface (%@)", activeInterface]];
        return FALSE;
    }
    
    int ret = setsockopt((int)fileDescriptor, IPPROTO_IP, IP_BOUND_IF, &interfaceIndex, sizeof(interfaceIndex));
    if (ret != 0) {
        [self logMessage:[NSString stringWithFormat: @"bindToDevice: setsockopt failed; errno: %d", errno]];
        return FALSE;
    }
    
    return TRUE;
}

/*!
 @brief Returns name of active network interface.
 @return Active interface name, nil otherwise.
 */
- (NSString *)getActiveInterface {
    
    // Getting list of all active interfaces
    NSMutableArray *upIffList = [NSMutableArray new];
    
    struct ifaddrs *interfaces;
    if (getifaddrs(&interfaces) != 0) {
        return nil;
    }
    
    struct ifaddrs *interface;
    for (interface=interfaces; interface; interface=interface->ifa_next) {
        
        // Only IFF_UP interfaces. Loopback is ignored.
        if (interface->ifa_flags & IFF_UP && !(interface->ifa_flags & IFF_LOOPBACK)) {
            
            if (interface->ifa_addr && (interface->ifa_addr->sa_family==AF_INET || interface->ifa_addr->sa_family==AF_INET6)) {
                
                NSString *interfaceName = [NSString stringWithUTF8String:interface->ifa_name];
                [upIffList addObject:interfaceName];
            }
        }
    }
    
    // Free getifaddrs data
    freeifaddrs(interfaces);
    
    [self logMessage:[NSString stringWithFormat:@"getActiveInterace: List of UP interfaces: %@", upIffList]];
    
    // TODO: following is a heuristic for choosing active network interface
    // Only Wi-Fi and Cellular interfaces are considered
    // @see : https://forums.developer.apple.com/thread/76711
    NSArray *iffPriorityList = @[ @"en0", @"pdp_ip0"];
    for (NSString * key in iffPriorityList) {
        for (NSString * upIff in upIffList) {
            if ([key isEqualToString:upIff]) {
                return [NSString stringWithString:upIff];
            }
        }
    }
    
    [self logMessage:@"getActiveInterface: No active interface found."];
    
    return nil;
}

- (NSString *)getPrimaryDnsServer {
    // This function is only called when BindToDevice is used/supported.
    // TODO: Implement correctly
    return @"8.8.8.8";
}

- (NSString *)getSecondaryDnsServer {
    // This function is only called when BindToDevice is used/supported.
    // TODO: Implement correctly
    return @"8.8.4.4";
}

- (long)hasNetworkConnectivity {
    BOOL hasConnectivity = [self->reachability currentReachabilityStatus] != NotReachable;

    if (!hasConnectivity) {
        // changeConnectionStateTo self-throttles, so even if called multiple
        // times it won't send multiple messages to the app.
        [self changeConnectionStateTo:PsiphonConnectionStateWaitingForNetwork evenIfSameState:NO];
    }

    return hasConnectivity;
}

- (NSString *)iPv6Synthesize:(NSString *)IPv4Addr {
    // This function is called to synthesize an ipv6 address from an ipv4 one on a DNS64/NAT64 network
    char *result = getIPv6ForIPv4([IPv4Addr UTF8String]);
    if (result != NULL) {
        NSString *IPv6Addr = [NSString stringWithUTF8String:result];
        free(result);
        return IPv6Addr;
    }
    return @"";
}

- (void)notice:(NSString *)noticeJSON {
    // To prevent out-of-control memory usage, we want to limit the number of notices
    // we asynchronously queue. Note that this means we'll start blocking Go threads
    // after the first notice, but that's still preferable to a memory explosion.
    dispatch_semaphore_wait(self->noticeHandlingSemaphore, DISPATCH_TIME_FOREVER);

    dispatch_async(self->workQueue, ^{
        [self handlePsiphonNotice:noticeJSON];
        dispatch_semaphore_signal(self->noticeHandlingSemaphore);
    });
}


#pragma mark - Helpers (private)

- (void)logMessage:(NSString *)message {
    if ([self.tunneledAppDelegate respondsToSelector:@selector(onDiagnosticMessage:)]) {
        dispatch_async(self->callbackQueue, ^{
            [self.tunneledAppDelegate onDiagnosticMessage:message];
        });
    }
}

- (void)changeConnectionStateTo:(PsiphonConnectionState)newState evenIfSameState:(BOOL)forceNotification {
    // Store the new state and get the old state.
    PsiphonConnectionState oldState = atomic_exchange(&self->connectionState, newState);

    // If the state has changed, inform the app.
    if (forceNotification || oldState != newState) {
        if ([self.tunneledAppDelegate respondsToSelector:@selector(onConnectionStateChangedFrom:to:)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onConnectionStateChangedFrom:oldState to:newState];
            });
        }

        if (newState == PsiphonConnectionStateDisconnected) {
            // This isn't a message sent to the app.
        }
        else if (newState == PsiphonConnectionStateConnecting &&
                 [self.tunneledAppDelegate respondsToSelector:@selector(onConnecting)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onConnecting];
            });
        }
        else if (newState == PsiphonConnectionStateConnected &&
                 [self.tunneledAppDelegate respondsToSelector:@selector(onConnected)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onConnected];
            });
        }
        else if (newState == PsiphonConnectionStateWaitingForNetwork &&
                 [self.tunneledAppDelegate respondsToSelector:@selector(onStartedWaitingForNetworkConnectivity)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onStartedWaitingForNetworkConnectivity];
            });
        }
    }
}

/*!
 Checks if the local SOCKS proxy is responding. 
 NOTE: This must only be called when there's a valid SOCKS proxy port (i.e., when
 we're in a connected state.)
 @return  TRUE if the local proxy is responding, FALSE otherwise.
 */
- (BOOL)isLocalProxyAlive {
    CFSocketRef sockfd;
    sockfd = CFSocketCreate(NULL, AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, NULL, NULL);
    if (sockfd == NULL) {
        // An error occurred creating the socket. It's impossible to complete
        // the test. We'll be optimistic.
        return YES;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_len = sizeof(servaddr);
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons([self getLocalSocksProxyPort]);
    inet_pton(AF_INET, [@"127.0.0.1" cStringUsingEncoding:NSUTF8StringEncoding], &servaddr.sin_addr);

    CFDataRef connectAddr = CFDataCreate(NULL, (unsigned char *)&servaddr, sizeof(servaddr));
    if (connectAddr == NULL) {
        CFSocketInvalidate(sockfd);
        CFRelease(sockfd);
        // Again, be optimistic.
        return YES;
    }

    BOOL proxyTestSuccess = YES;
    if (CFSocketConnectToAddress(sockfd, connectAddr, 1) != kCFSocketSuccess) {
        proxyTestSuccess = NO;
    }

    CFSocketInvalidate(sockfd);
    CFRelease(sockfd);
    CFRelease(connectAddr);

    return proxyTestSuccess;
}

// We are going to do our own monitoring of the network reachability, rather
// than relying on the tunnel to inform us. This is because it can take a long
// time for the tunnel to notice the network is gone (depending on attempts to
// use the tunnel).
- (void)startInternetReachabilityMonitoring {
    self->previousNetworkStatus = [self->reachability currentReachabilityStatus];

    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(internetReachabilityChanged:) name:kReachabilityChangedNotification object:nil];
    [self->reachability startNotifier];
}

- (void)stopInternetReachabilityMonitoring {
    [self->reachability stopNotifier];
    [[NSNotificationCenter defaultCenter] removeObserver:self name:kReachabilityChangedNotification object:nil];
}

- (void)internetReachabilityChanged:(NSNotification *)note
{
    // If we lose network while connected, we're going to force a reconnect in
    // order to trigger the waiting-for-network state. The reason we don't wait
    // for the tunnel to notice the network loss is that it might take 30 seconds.

    Reachability* currentReachability = [note object];
    NetworkStatus networkStatus = [currentReachability currentReachabilityStatus];

    PsiphonConnectionState currentConnectionState = [self getConnectionState];

    if (currentConnectionState == PsiphonConnectionStateConnected &&
        self->previousNetworkStatus != NotReachable &&
        self->previousNetworkStatus != networkStatus) {
        if ([self.tunneledAppDelegate respondsToSelector:@selector(onDeviceInternetConnectivityInterrupted)]) {
            dispatch_async(self->callbackQueue, ^{
                [self.tunneledAppDelegate onDeviceInternetConnectivityInterrupted];
            });
        }
    }

    self->previousNetworkStatus = networkStatus;
}

/*!
 Determine the device's region. Makes a best guess based on available info.
 @returns The two-letter country code that the device is probably located in.
 */
+ (NSString * _Nonnull)getDeviceRegion {
    /// One of the ways we determine the device region is to look at the current timezone. When then need to map that to a likely country.
    /// This mapping is derived from here: https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
    const NSDictionary *timezoneToCountryCode = @{@"Africa/Abidjan": @"CI", @"Africa/Accra": @"GH", @"Africa/Addis_Ababa": @"ET", @"Africa/Algiers": @"DZ", @"Africa/Asmara": @"ER", @"Africa/Bamako": @"ML", @"Africa/Bangui": @"CF", @"Africa/Banjul": @"GM", @"Africa/Bissau": @"GW", @"Africa/Blantyre": @"MW", @"Africa/Brazzaville": @"CG", @"Africa/Bujumbura": @"BI", @"Africa/Cairo": @"EG", @"Africa/Casablanca": @"MA", @"Africa/Ceuta": @"ES", @"Africa/Conakry": @"GN", @"Africa/Dakar": @"SN", @"Africa/Dar_es_Salaam": @"TZ", @"Africa/Djibouti": @"DJ", @"Africa/Douala": @"CM", @"Africa/El_Aaiun": @"EH", @"Africa/Freetown": @"SL", @"Africa/Gaborone": @"BW", @"Africa/Harare": @"ZW", @"Africa/Johannesburg": @"ZA", @"Africa/Juba": @"SS", @"Africa/Kampala": @"UG", @"Africa/Khartoum": @"SD", @"Africa/Kigali": @"RW", @"Africa/Kinshasa": @"CD", @"Africa/Lagos": @"NG", @"Africa/Libreville": @"GA", @"Africa/Lome": @"TG", @"Africa/Luanda": @"AO", @"Africa/Lubumbashi": @"CD", @"Africa/Lusaka": @"ZM", @"Africa/Malabo": @"GQ", @"Africa/Maputo": @"MZ", @"Africa/Maseru": @"LS", @"Africa/Mbabane": @"SZ", @"Africa/Mogadishu": @"SO", @"Africa/Monrovia": @"LR", @"Africa/Nairobi": @"KE", @"Africa/Ndjamena": @"TD", @"Africa/Niamey": @"NE", @"Africa/Nouakchott": @"MR", @"Africa/Ouagadougou": @"BF", @"Africa/Porto-Novo": @"BJ", @"Africa/Sao_Tome": @"ST", @"Africa/Tripoli": @"LY", @"Africa/Tunis": @"TN", @"Africa/Windhoek": @"NA", @"America/Adak": @"US", @"America/Anchorage": @"US", @"America/Anguilla": @"AI", @"America/Antigua": @"AG", @"America/Araguaina": @"BR", @"America/Argentina/Buenos_Aires": @"AR", @"America/Argentina/Catamarca": @"AR", @"America/Argentina/Cordoba": @"AR", @"America/Argentina/Jujuy": @"AR", @"America/Argentina/La_Rioja": @"AR", @"America/Argentina/Mendoza": @"AR", @"America/Argentina/Rio_Gallegos": @"AR", @"America/Argentina/Salta": @"AR", @"America/Argentina/San_Juan": @"AR", @"America/Argentina/San_Luis": @"AR", @"America/Argentina/Tucuman": @"AR", @"America/Argentina/Ushuaia": @"AR", @"America/Aruba": @"AW", @"America/Asuncion": @"PY", @"America/Atikokan": @"CA", @"America/Bahia": @"BR", @"America/Bahia_Banderas": @"MX", @"America/Barbados": @"BB", @"America/Belem": @"BR", @"America/Belize": @"BZ", @"America/Blanc-Sablon": @"CA", @"America/Boa_Vista": @"BR", @"America/Bogota": @"CO", @"America/Boise": @"US", @"America/Cambridge_Bay": @"CA", @"America/Campo_Grande": @"BR", @"America/Cancun": @"MX", @"America/Caracas": @"VE", @"America/Cayenne": @"GF", @"America/Cayman": @"KY", @"America/Chicago": @"US", @"America/Chihuahua": @"MX", @"America/Costa_Rica": @"CR", @"America/Creston": @"CA", @"America/Cuiaba": @"BR", @"America/Curacao": @"CW", @"America/Danmarkshavn": @"GL", @"America/Dawson": @"CA", @"America/Dawson_Creek": @"CA", @"America/Denver": @"US", @"America/Detroit": @"US", @"America/Dominica": @"DM", @"America/Edmonton": @"CA", @"America/Eirunepe": @"BR", @"America/El_Salvador": @"SV", @"America/Fort_Nelson": @"CA", @"America/Fortaleza": @"BR", @"America/Glace_Bay": @"CA", @"America/Godthab": @"GL", @"America/Goose_Bay": @"CA", @"America/Grand_Turk": @"TC", @"America/Grenada": @"GD", @"America/Guadeloupe": @"GP", @"America/Guatemala": @"GT", @"America/Guayaquil": @"EC", @"America/Guyana": @"GY", @"America/Halifax": @"CA", @"America/Havana": @"CU", @"America/Hermosillo": @"MX", @"America/Indiana/Indianapolis": @"US", @"America/Indiana/Knox": @"US", @"America/Indiana/Marengo": @"US", @"America/Indiana/Petersburg": @"US", @"America/Indiana/Tell_City": @"US", @"America/Indiana/Vevay": @"US", @"America/Indiana/Vincennes": @"US", @"America/Indiana/Winamac": @"US", @"America/Inuvik": @"CA", @"America/Iqaluit": @"CA", @"America/Jamaica": @"JM", @"America/Juneau": @"US", @"America/Kentucky/Louisville": @"US", @"America/Kentucky/Monticello": @"US", @"America/Kralendijk": @"BQ", @"America/La_Paz": @"BO", @"America/Lima": @"PE", @"America/Los_Angeles": @"US", @"America/Lower_Princes": @"SX", @"America/Maceio": @"BR", @"America/Managua": @"NI", @"America/Manaus": @"BR", @"America/Marigot": @"MF", @"America/Martinique": @"MQ", @"America/Matamoros": @"MX", @"America/Mazatlan": @"MX", @"America/Menominee": @"US", @"America/Merida": @"MX", @"America/Metlakatla": @"US", @"America/Mexico_City": @"MX", @"America/Miquelon": @"PM", @"America/Moncton": @"CA", @"America/Monterrey": @"MX", @"America/Montevideo": @"UY", @"America/Montserrat": @"MS", @"America/Nassau": @"BS", @"America/New_York": @"US", @"America/Nipigon": @"CA", @"America/Nome": @"US", @"America/Noronha": @"BR", @"America/North_Dakota/Beulah": @"US", @"America/North_Dakota/Center": @"US", @"America/North_Dakota/New_Salem": @"US", @"America/Ojinaga": @"MX", @"America/Panama": @"PA", @"America/Pangnirtung": @"CA", @"America/Paramaribo": @"SR", @"America/Phoenix": @"US", @"America/Port_of_Spain": @"TT", @"America/Port-au-Prince": @"HT", @"America/Porto_Velho": @"BR", @"America/Puerto_Rico": @"PR", @"America/Rainy_River": @"CA", @"America/Rankin_Inlet": @"CA", @"America/Recife": @"BR", @"America/Regina": @"CA", @"America/Resolute": @"CA", @"America/Rio_Branco": @"BR", @"America/Santarem": @"BR", @"America/Santiago": @"CL", @"America/Santo_Domingo": @"DO", @"America/Sao_Paulo": @"BR", @"America/Scoresbysund": @"GL", @"America/Sitka": @"US", @"America/St_Barthelemy": @"BL", @"America/St_Johns": @"CA", @"America/St_Kitts": @"KN", @"America/St_Lucia": @"LC", @"America/St_Thomas": @"VI", @"America/St_Vincent": @"VC", @"America/Swift_Current": @"CA", @"America/Tegucigalpa": @"HN", @"America/Thule": @"GL", @"America/Thunder_Bay": @"CA", @"America/Tijuana": @"MX", @"America/Toronto": @"CA", @"America/Tortola": @"VG", @"America/Vancouver": @"CA", @"America/Whitehorse": @"CA", @"America/Winnipeg": @"CA", @"America/Yakutat": @"US", @"America/Yellowknife": @"CA", @"Antarctica/Casey": @"AQ", @"Antarctica/Davis": @"AQ", @"Antarctica/DumontDUrville": @"AQ", @"Antarctica/Macquarie": @"AU", @"Antarctica/Mawson": @"AQ", @"Antarctica/McMurdo": @"AQ", @"Antarctica/Palmer": @"AQ", @"Antarctica/Rothera": @"AQ", @"Antarctica/Syowa": @"AQ", @"Antarctica/Troll": @"AQ", @"Antarctica/Vostok": @"AQ", @"Arctic/Longyearbyen": @"SJ", @"Asia/Aden": @"YE", @"Asia/Almaty": @"KZ", @"Asia/Amman": @"JO", @"Asia/Anadyr": @"RU", @"Asia/Aqtau": @"KZ", @"Asia/Aqtobe": @"KZ", @"Asia/Ashgabat": @"TM", @"Asia/Baghdad": @"IQ", @"Asia/Bahrain": @"BH", @"Asia/Baku": @"AZ", @"Asia/Bangkok": @"TH", @"Asia/Barnaul": @"RU", @"Asia/Beirut": @"LB", @"Asia/Bishkek": @"KG", @"Asia/Brunei": @"BN", @"Asia/Chita": @"RU", @"Asia/Choibalsan": @"MN", @"Asia/Colombo": @"LK", @"Asia/Damascus": @"SY", @"Asia/Dhaka": @"BD", @"Asia/Dili": @"TL", @"Asia/Dubai": @"AE", @"Asia/Dushanbe": @"TJ", @"Asia/Gaza": @"PS", @"Asia/Hebron": @"PS", @"Asia/Ho_Chi_Minh": @"VN", @"Asia/Hong_Kong": @"HK", @"Asia/Hovd": @"MN", @"Asia/Irkutsk": @"RU", @"Asia/Jakarta": @"ID", @"Asia/Jayapura": @"ID", @"Asia/Jerusalem": @"IL", @"Asia/Kabul": @"AF", @"Asia/Kamchatka": @"RU", @"Asia/Karachi": @"PK", @"Asia/Kathmandu": @"NP", @"Asia/Khandyga": @"RU", @"Asia/Kolkata": @"IN", @"Asia/Krasnoyarsk": @"RU", @"Asia/Kuala_Lumpur": @"MY", @"Asia/Kuching": @"MY", @"Asia/Kuwait": @"KW", @"Asia/Macau": @"MO", @"Asia/Magadan": @"RU", @"Asia/Makassar": @"ID", @"Asia/Manila": @"PH", @"Asia/Muscat": @"OM", @"Asia/Nicosia": @"CY", @"Asia/Novokuznetsk": @"RU", @"Asia/Novosibirsk": @"RU", @"Asia/Omsk": @"RU", @"Asia/Oral": @"KZ", @"Asia/Phnom_Penh": @"KH", @"Asia/Pontianak": @"ID", @"Asia/Pyongyang": @"KP", @"Asia/Qatar": @"QA", @"Asia/Qyzylorda": @"KZ", @"Asia/Rangoon": @"MM", @"Asia/Riyadh": @"SA", @"Asia/Sakhalin": @"RU", @"Asia/Samarkand": @"UZ", @"Asia/Seoul": @"KR", @"Asia/Shanghai": @"CN", @"Asia/Singapore": @"SG", @"Asia/Srednekolymsk": @"RU", @"Asia/Taipei": @"TW", @"Asia/Tashkent": @"UZ", @"Asia/Tbilisi": @"GE", @"Asia/Tehran": @"IR", @"Asia/Thimphu": @"BT", @"Asia/Tokyo": @"JP", @"Asia/Tomsk": @"RU", @"Asia/Ulaanbaatar": @"MN", @"Asia/Urumqi": @"CN", @"Asia/Ust-Nera": @"RU", @"Asia/Vientiane": @"LA", @"Asia/Vladivostok": @"RU", @"Asia/Yakutsk": @"RU", @"Asia/Yekaterinburg": @"RU", @"Asia/Yerevan": @"AM", @"Atlantic/Azores": @"PT", @"Atlantic/Bermuda": @"BM", @"Atlantic/Canary": @"ES", @"Atlantic/Cape_Verde": @"CV", @"Atlantic/Faroe": @"FO", @"Atlantic/Madeira": @"PT", @"Atlantic/Reykjavik": @"IS", @"Atlantic/South_Georgia": @"GS", @"Atlantic/St_Helena": @"SH", @"Atlantic/Stanley": @"FK", @"Australia/Adelaide": @"AU", @"Australia/Brisbane": @"AU", @"Australia/Broken_Hill": @"AU", @"Australia/Currie": @"AU", @"Australia/Darwin": @"AU", @"Australia/Eucla": @"AU", @"Australia/Hobart": @"AU", @"Australia/Lindeman": @"AU", @"Australia/Lord_Howe": @"AU", @"Australia/Melbourne": @"AU", @"Australia/Perth": @"AU", @"Australia/Sydney": @"AU", @"Europe/Amsterdam": @"NL", @"Europe/Andorra": @"AD", @"Europe/Astrakhan": @"RU", @"Europe/Athens": @"GR", @"Europe/Belgrade": @"RS", @"Europe/Berlin": @"DE", @"Europe/Bratislava": @"SK", @"Europe/Brussels": @"BE", @"Europe/Bucharest": @"RO", @"Europe/Budapest": @"HU", @"Europe/Busingen": @"DE", @"Europe/Chisinau": @"MD", @"Europe/Copenhagen": @"DK", @"Europe/Dublin": @"IE", @"Europe/Gibraltar": @"GI", @"Europe/Guernsey": @"GG", @"Europe/Helsinki": @"FI", @"Europe/Isle_of_Man": @"IM", @"Europe/Istanbul": @"TR", @"Europe/Jersey": @"JE", @"Europe/Kaliningrad": @"RU", @"Europe/Kiev": @"UA", @"Europe/Kirov": @"RU", @"Europe/Lisbon": @"PT", @"Europe/Ljubljana": @"SI", @"Europe/London": @"GB", @"Europe/Luxembourg": @"LU", @"Europe/Madrid": @"ES", @"Europe/Malta": @"MT", @"Europe/Mariehamn": @"AX", @"Europe/Minsk": @"BY", @"Europe/Monaco": @"MC", @"Europe/Moscow": @"RU", @"Europe/Oslo": @"NO", @"Europe/Paris": @"FR", @"Europe/Podgorica": @"ME", @"Europe/Prague": @"CZ", @"Europe/Riga": @"LV", @"Europe/Rome": @"IT", @"Europe/Samara": @"RU", @"Europe/San_Marino": @"SM", @"Europe/Sarajevo": @"BA", @"Europe/Simferopol": @"RU", @"Europe/Skopje": @"MK", @"Europe/Sofia": @"BG", @"Europe/Stockholm": @"SE", @"Europe/Tallinn": @"EE", @"Europe/Tirane": @"AL", @"Europe/Ulyanovsk": @"RU", @"Europe/Uzhgorod": @"UA", @"Europe/Vaduz": @"LI", @"Europe/Vatican": @"VA", @"Europe/Vienna": @"AT", @"Europe/Vilnius": @"LT", @"Europe/Volgograd": @"RU", @"Europe/Warsaw": @"PL", @"Europe/Zagreb": @"HR", @"Europe/Zaporozhye": @"UA", @"Europe/Zurich": @"CH", @"Indian/Antananarivo": @"MG", @"Indian/Chagos": @"IO", @"Indian/Christmas": @"CX", @"Indian/Cocos": @"CC", @"Indian/Comoro": @"KM", @"Indian/Kerguelen": @"TF", @"Indian/Mahe": @"SC", @"Indian/Maldives": @"MV", @"Indian/Mauritius": @"MU", @"Indian/Mayotte": @"YT", @"Indian/Reunion": @"RE", @"Pacific/Apia": @"WS", @"Pacific/Auckland": @"NZ", @"Pacific/Bougainville": @"PG", @"Pacific/Chatham": @"NZ", @"Pacific/Chuuk": @"FM", @"Pacific/Easter": @"CL", @"Pacific/Efate": @"VU", @"Pacific/Enderbury": @"KI", @"Pacific/Fakaofo": @"TK", @"Pacific/Fiji": @"FJ", @"Pacific/Funafuti": @"TV", @"Pacific/Galapagos": @"EC", @"Pacific/Gambier": @"PF", @"Pacific/Guadalcanal": @"SB", @"Pacific/Guam": @"GU", @"Pacific/Honolulu": @"US", @"Pacific/Johnston": @"UM", @"Pacific/Kiritimati": @"KI", @"Pacific/Kosrae": @"FM", @"Pacific/Kwajalein": @"MH", @"Pacific/Majuro": @"MH", @"Pacific/Marquesas": @"PF", @"Pacific/Midway": @"UM", @"Pacific/Nauru": @"NR", @"Pacific/Niue": @"NU", @"Pacific/Norfolk": @"NF", @"Pacific/Noumea": @"NC", @"Pacific/Pago_Pago": @"AS", @"Pacific/Palau": @"PW", @"Pacific/Pitcairn": @"PN", @"Pacific/Pohnpei": @"FM", @"Pacific/Port_Moresby": @"PG", @"Pacific/Rarotonga": @"CK", @"Pacific/Saipan": @"MP", @"Pacific/Tahiti": @"PF", @"Pacific/Tarawa": @"KI", @"Pacific/Tongatapu": @"TO", @"Pacific/Wake": @"UM", @"Pacific/Wallis": @"WF"};
    
    // First try getting from telephony info (will fail for non-phones and simulator)
    CTTelephonyNetworkInfo *networkInfo = nil;
    CTCarrier *carrier = nil;
    NSString *carrierCountryCode = nil;
    if ((networkInfo = [[CTTelephonyNetworkInfo alloc] init]) != nil &&
        (carrier = [networkInfo subscriberCellularProvider]) != nil &&
        (carrierCountryCode = [carrier isoCountryCode]) != nil) {
        return [carrierCountryCode uppercaseString];
    }
    
    // Next try to map the time zone to a country code.
    NSString *timezone = [[NSTimeZone systemTimeZone] name];
    if (timezoneToCountryCode[timezone] != nil) {
        return timezoneToCountryCode[timezone];
    }
    
    // Next try getting the region from the current locale. This isn't terribly
    // reliable (because, for example, en-US is used in a lot of places that
    // aren't the US).
    NSString *localeCountryCode = [[NSLocale currentLocale] objectForKey:NSLocaleCountryCode];
    
    if (localeCountryCode != nil) {
        return [localeCountryCode uppercaseString];
    }
    
    // Generic-ish default
    return @"US";
}

@end
