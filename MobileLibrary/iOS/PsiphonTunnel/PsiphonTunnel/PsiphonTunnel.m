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

#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <Psi/Psi.h>
#import "PsiphonTunnel.h"
#import "Reachability.h"
#import "json-framework/SBJson4.h"


@interface PsiphonTunnel () <GoPsiPsiphonProvider>

@property (weak) id <TunneledAppDelegate> tunneledAppDelegate;

@end

@implementation PsiphonTunnel

#pragma mark - PsiphonTunnel public methods

// See comment in header
+(PsiphonTunnel * _Nonnull) newPsiphonTunnel:(id<TunneledAppDelegate> _Nonnull)tunneledAppDelegate {
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
-(BOOL) start:(NSString * _Nullable)embeddedServerEntries {
    @synchronized (PsiphonTunnel.self) {
        [self stop];
        [self.tunneledAppDelegate onDiagnosticMessage:@"Starting Psiphon library"];

        // Not supported on iOS.
        const BOOL useDeviceBinder = FALSE;
        
        NSString *configStr = [self getConfig];
        if (configStr == nil) {
            return FALSE;
        }

        @try {
            NSError *e = nil;
            
            BOOL res = GoPsiStart(
                           configStr,
                           embeddedServerEntries,
                           self,
                           useDeviceBinder,
                           &e);
            
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"GoPsiStart: %@", res ? @"TRUE" : @"FALSE"]];
            
            if (e != nil) {
                [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"Psiphon tunnel start failed: %@", e.localizedDescription]];
                return FALSE;
            }
        }
        @catch(NSException *exception) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"Failed to start Psiphon library: %@", exception.reason]];
        }
        [self.tunneledAppDelegate onDiagnosticMessage:@"Psiphon tunnel started"];
        
        return TRUE;
    }
}

// See comment in header.
-(void) stop {
    @synchronized (PsiphonTunnel.self) {
        [self.tunneledAppDelegate onDiagnosticMessage: @"Stopping Psiphon library"];
        GoPsiStop();
        [self.tunneledAppDelegate onDiagnosticMessage: @"Psiphon library stopped"];
    }
}

// See comment in header.
+ (void)sendFeedback:(NSString * _Nonnull)connectionConfigJson diagnostics:(NSString * _Nonnull)diagnosticsJson publicKey:(NSString * _Nonnull)b64EncodedPublicKey uploadServer:(NSString * _Nonnull)uploadServer uploadPath:(NSString * _Nonnull)uploadPath uploadServerHeaders:(NSString * _Nonnull)uploadServerHeaders {
    GoPsiSendFeedback(connectionConfigJson, diagnosticsJson, b64EncodedPublicKey, uploadServer, uploadPath, uploadServerHeaders);
}


#pragma mark - PsiphonTunnel logic implementation methods (private)

/*!
 Build the config string for the tunnel.
 @returns String containing the JSON config. `nil` on error.
 */
-(NSString * _Nullable)getConfig {
    // tunneledAppDelegate is a weak reference, so check it.
    if (self.tunneledAppDelegate == nil) {
        [self.tunneledAppDelegate onDiagnosticMessage:@"tunneledApp delegate lost"];
        return nil;
    }
    
    NSString *configStr = [self.tunneledAppDelegate getPsiphonConfig];
    if (configStr == nil) {
        [self.tunneledAppDelegate onDiagnosticMessage:@"Error getting config from delegate"];
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
        [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"Config JSON parse failed: %@", err.description]];
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
        [self.tunneledAppDelegate onDiagnosticMessage:@"Config missing PropagationChannelId"];
        return nil;
    }

    if (config[@"SponsorId"] == nil) {
        [self.tunneledAppDelegate onDiagnosticMessage:@"Config missing SponsorId"];
        return nil;
    }
    
    //
    // Fill in optional config values.
    //
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    NSError* err = nil;
    NSURL *libraryURL = [fileManager URLForDirectory:NSLibraryDirectory inDomain:NSUserDomainMask appropriateForURL:nil create:YES error:&err];
    
    if (libraryURL == nil) {
        [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"Unable to get Library URL: %@", err.localizedDescription]];
        return nil;
    }
    
    // Some clients will have a data directory that they'd prefer the Psiphon
    // library use, but if not we'll default to the user Library directory.
    NSURL *defaultDataStoreDirectoryURL = [libraryURL URLByAppendingPathComponent:@"datastore" isDirectory:YES];
    
    if (defaultDataStoreDirectoryURL == nil) {
        [self.tunneledAppDelegate onDiagnosticMessage:@"Unable to create defaultDataStoreDirectoryURL"];
        return nil;
    }
    
    if (config[@"DataStoreDirectory"] == nil) {
        [fileManager createDirectoryAtURL:defaultDataStoreDirectoryURL withIntermediateDirectories:YES attributes:nil error:&err];
        if (err != nil) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"Unable to create defaultDataStoreDirectoryURL: %@", err.localizedDescription]];
            return nil;
        }
        
        config[@"DataStoreDirectory"] = [defaultDataStoreDirectoryURL path];
    }
    else {
        [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"DataStoreDirectory overridden from '%@' to '%@'", [defaultDataStoreDirectoryURL path], config[@"DataStoreDirectory"]]];
    }
    
    // See previous comment.
    NSString *defaultRemoteServerListFilename = [[libraryURL URLByAppendingPathComponent:@"remote_server_list" isDirectory:NO] path];
    
    if (defaultRemoteServerListFilename == nil) {
        [self.tunneledAppDelegate onDiagnosticMessage:@"Unable to create defaultRemoteServerListFilename"];
        return nil;
    }
    
    if (config[@"RemoteServerListDownloadFilename"] == nil) {
        config[@"RemoteServerListDownloadFilename"] = defaultRemoteServerListFilename;
    }
    else {
        [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"RemoteServerListDownloadFilename overridden from '%@' to '%@'", defaultRemoteServerListFilename, config[@"RemoteServerListDownloadFilename"]]];
    }
    
    // If RemoteServerListUrl and RemoteServerListSignaturePublicKey are absent,
    // we'll just leave them out, but we'll log about it.
    if (config[@"RemoteServerListUrl"] == nil ||
        config[@"RemoteServerListSignaturePublicKey"] == nil) {
        [self.tunneledAppDelegate onDiagnosticMessage:@"Remote server list functionality will be disabled"];
    }

    // Other optional fields not being altered. If not set, their defaults will be used:
    // * EstablishTunnelTimeoutSeconds
    // * TunnelWholeDevice
    // * LocalSocksProxyPort
    // * LocalHttpProxyPort
    // * UpstreamProxyUrl
    // * EmitDiagnosticNotices
    // * EgressRegion
    // * UpgradeDownloadUrl
    // * UpgradeDownloadClientVersionHeader
    // * UpgradeDownloadFilename
    // * timeout fields
    
    // TODO: Is LocalSocksProxyPort relevant for iOS?
    
    //
    // Fill in the rest of the values.
    //
    
    // TODO: Should be configurable?
    config[@"EmitBytesTransferred"] = [NSNumber numberWithBool:TRUE];

    config[@"DeviceRegion"] = [PsiphonTunnel getDeviceRegion];
    
    config[@"UseIndistinguishableTLS"] = [NSNumber numberWithBool:FALSE];
    
    // Get the location of the root CAs file in the bundle resources.
    NSURL *rootCAsURL = [[NSBundle bundleForClass:[self class]] URLForResource:@"rootCAs" withExtension:@"txt"];
    NSString *bundledTrustedCAPath = nil;
    if (rootCAsURL == nil ||
        (bundledTrustedCAPath = [rootCAsURL path]) == nil ||
        ![[NSFileManager defaultManager] fileExistsAtPath:bundledTrustedCAPath]) {
        [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"Unable to find Root CAs file in bundle: %@", bundledTrustedCAPath]];
        return nil;
    }
    config[@"TrustedCACertificatesFilename"] = bundledTrustedCAPath;
    
    //
    // Many other fields must *only* be modified by official Psiphon clients.
    // Some of them require default values.
    //
    
    // TODO: After updating tunnel-core in the framework, verify that this value is getting through to Kibana.
    if (config[@"ClientPlatform"] == nil) {
        config[@"ClientPlatform"] = @"iOS-Library";
    }
    else {
        [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"ClientPlatform overridden from 'iOS-Library' to '%@'", config[@"ClientPlatform"]]];
    }

    NSString *finalConfigStr = [[[SBJson4Writer alloc] init] stringWithObject:config];
    
    if (finalConfigStr == nil) {
        [self.tunneledAppDelegate onDiagnosticMessage:@"Failed to convert config to JSON string"];
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
        [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"Notice JSON parse failed: %@", err.description]];
    };
    
    id parser = [SBJson4Parser parserWithBlock:block allowMultiRoot:NO unwrapRootArray:NO errorHandler:eh];
    [parser parse:[noticeJSON dataUsingEncoding:NSUTF8StringEncoding]];
    
    if (notice == nil) {
        return;
    }

    NSString *noticeType = notice[@"noticeType"];
    if (noticeType == nil) {
        [self.tunneledAppDelegate onDiagnosticMessage:@"Notice missing noticeType"];
        return;
    }
    
    if ([noticeType isEqualToString:@"Tunnels"]) {
        id count = [notice valueForKeyPath:@"data.count"];
        if (![count isKindOfClass:[NSNumber class]]) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"Tunnels notice missing data.count: %@", noticeJSON]];
            return;
        }

        if ([count integerValue] > 0) {
            [self.tunneledAppDelegate onConnected];
        } else {
            [self.tunneledAppDelegate onConnecting];
        }
    }
    else if ([noticeType isEqualToString:@"Exiting"]) {
        [self.tunneledAppDelegate onExiting];
    }
    else if ([noticeType isEqualToString:@"AvailableEgressRegions"]) {
        id regions = [notice valueForKeyPath:@"data.regions"];
        if (![regions isKindOfClass:[NSArray class]]) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"AvailableEgressRegions notice missing data.regions: %@", noticeJSON]];
            return;
        }

        [self.tunneledAppDelegate onAvailableEgressRegions:regions];
    }
    else if ([noticeType isEqualToString:@"SocksProxyPortInUse"]) {
        id port = [notice valueForKeyPath:@"data.port"];
        if (![port isKindOfClass:[NSNumber class]]) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"SocksProxyPortInUse notice missing data.port: %@", noticeJSON]];
            return;
        }

        [self.tunneledAppDelegate onSocksProxyPortInUse:[port integerValue]];
    }
    else if ([noticeType isEqualToString:@"HttpProxyPortInUse"]) {
        id port = [notice valueForKeyPath:@"data.port"];
        if (![port isKindOfClass:[NSNumber class]]) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"HttpProxyPortInUse notice missing data.port: %@", noticeJSON]];
            return;
        }
        
        [self.tunneledAppDelegate onHttpProxyPortInUse:[port integerValue]];
    }
    else if ([noticeType isEqualToString:@"ListeningSocksProxyPort"]) {
        id port = [notice valueForKeyPath:@"data.port"];
        if (![port isKindOfClass:[NSNumber class]]) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"ListeningSocksProxyPort notice missing data.port: %@", noticeJSON]];
            return;
        }
        
        [self.tunneledAppDelegate onListeningSocksProxyPort:[port integerValue]];
    }
    else if ([noticeType isEqualToString:@"ListeningHttpProxyPort"]) {
        id port = [notice valueForKeyPath:@"data.port"];
        if (![port isKindOfClass:[NSNumber class]]) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"ListeningHttpProxyPort notice missing data.port: %@", noticeJSON]];
            return;
        }
        
        [self.tunneledAppDelegate onListeningHttpProxyPort:[port integerValue]];
    }
    else if ([noticeType isEqualToString:@"UpstreamProxyError"]) {
        id message = [notice valueForKeyPath:@"data.message"];
        if (![message isKindOfClass:[NSString class]]) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"UpstreamProxyError notice missing data.message: %@", noticeJSON]];
            return;
        }
        
        [self.tunneledAppDelegate onUpstreamProxyError:message];
    }
    else if ([noticeType isEqualToString:@"ClientUpgradeDownloaded"]) {
        id filename = [notice valueForKeyPath:@"data.filename"];
        if (![filename isKindOfClass:[NSString class]]) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"ClientUpgradeDownloaded notice missing data.filename: %@", noticeJSON]];
            return;
        }
        
        [self.tunneledAppDelegate onClientUpgradeDownloaded:filename];
    }
    else if ([noticeType isEqualToString:@"ClientIsLatestVersion"]) {
        [self.tunneledAppDelegate onClientIsLatestVersion];
    }
    else if ([noticeType isEqualToString:@"Homepage"]) {
        id url = [notice valueForKeyPath:@"data.url"];
        if (![url isKindOfClass:[NSString class]]) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"Homepage notice missing data.url: %@", noticeJSON]];
            return;
        }
        
        [self.tunneledAppDelegate onHomepage:url];
    }
    else if ([noticeType isEqualToString:@"ClientRegion"]) {
        id region = [notice valueForKeyPath:@"data.region"];
        if (![region isKindOfClass:[NSString class]]) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"ClientRegion notice missing data.region: %@", noticeJSON]];
            return;
        }
        
        [self.tunneledAppDelegate onClientRegion:region];
    }
    else if ([noticeType isEqualToString:@"SplitTunnelRegion"]) {
        id region = [notice valueForKeyPath:@"data.region"];
        if (![region isKindOfClass:[NSString class]]) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"SplitTunnelRegion notice missing data.region: %@", noticeJSON]];
            return;
        }
        
        [self.tunneledAppDelegate onSplitTunnelRegion:region];
    }
    else if ([noticeType isEqualToString:@"Untunneled"]) {
        id address = [notice valueForKeyPath:@"data.address"];
        if (![address isKindOfClass:[NSString class]]) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"Untunneled notice missing data.address: %@", noticeJSON]];
            return;
        }
        
        [self.tunneledAppDelegate onUntunneledAddress:address];
    }
    else if ([noticeType isEqualToString:@"BytesTransferred"]) {
        diagnostic = FALSE;
        
        id sent = [notice valueForKeyPath:@"data.sent"];
        id received = [notice valueForKeyPath:@"data.received"];
        if (![sent isKindOfClass:[NSNumber class]] || ![received isKindOfClass:[NSNumber class]]) {
            [self.tunneledAppDelegate onDiagnosticMessage:[NSString stringWithFormat: @"BytesTransferred notice missing data.sent or data.received: %@", noticeJSON]];
            return;
        }
        
        [self.tunneledAppDelegate onBytesTransferred:[sent longLongValue]:[received longLongValue]];
    }
    
    // Pass diagnostic messages to onDiagnosticMessage.
    if (diagnostic) {
        NSDictionary *data = notice[@"data"];
        if (data == nil) {
            return;
        }
        
        NSString *dataStr = [[[SBJson4Writer alloc] init] stringWithObject:data];

        NSString *diagnosticMessage = [NSString stringWithFormat:@"%@: %@", noticeType, dataStr];
        [self. tunneledAppDelegate onDiagnosticMessage:diagnosticMessage];
    }
}


#pragma mark - GoPsiPsiphonProvider protocol implementation (private)

- (BOOL)bindToDevice:(long)fileDescriptor error:(NSError **)error {
    // This PsiphonProvider function is only called in TunnelWholeDevice mode
    return TRUE;
}

- (NSString *)getPrimaryDnsServer {
    // This function is only called when BindToDevice is used/supported.
    return @"8.8.8.8";
}

- (NSString *)getSecondaryDnsServer {
    // This function is only called when BindToDevice is used/supported.
    return @"8.8.4.4";
}

- (long)hasNetworkConnectivity {
    Reachability *reachability = [Reachability reachabilityForInternetConnection];
    NetworkStatus netstat = [reachability currentReachabilityStatus];
    return (netstat != NotReachable) ? 1 : 0;
}

- (void)notice:(NSString *)noticeJSON {
    [self handlePsiphonNotice:noticeJSON];
}


#pragma mark - Helpers (private)

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
