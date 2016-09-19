//
//  TunnelManager.swift
//  TunneledWebView
//

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

import Foundation
import CoreTelephony

import Psi

public protocol TunneledAppDelegate: class {
    /// Called when tunnel is started to get the library consumer's desired configuration.
    ///
    /// **Required fields:**
    /// * `PropagationChannelId`
    /// * `SponsorId`
    /// * Remote server list functionality is not strictly required, but absence greatly undermines circumvention ability.
    ///   * `RemoteServerListUrl`
    ///   * `RemoteServerListSignaturePublicKey`
    ///
    /// **Optional fields** (if you don't need them, don't set them):
    /// * `DataStoreDirectory`: If not set, the library will use a sane location. Override if the client wants to restrict where operational data is kept.
    /// * `RemoteServerListDownloadFilename`: See comment for `DataStoreDirectory`.
    /// * `ClientPlatform`: Should not be set by most library consumers.
    /// * `UpstreamProxyUrl`
    /// * `EmitDiagnosticNotices`
    /// * `LocalHttpProxyPort` // TODO: Should this be set-able for iOS?
    /// * `LocalSocksProxyPort` // TODO: Should this be set-able for iOS?
    /// * `EgressRegion`
    /// * `EstablishTunnelTimeoutSeconds`
    /// * `TunnelWholeDevice`: For stats purposes, but must be accurate. Defaults to 0 (false).
    /// * Should only be set if the Psiphon library is handling upgrade downloading (which it usually is _not_):
    ///   * `UpgradeDownloadUrl`
    ///   * `UpgradeDownloadClientVersionHeader`
    ///   * `UpgradeDownloadFilename`
    /// * Only set if disabling timeouts (for very slow network connections):
    ///   * `TunnelConnectTimeoutSeconds`
    ///   * `TunnelPortForwardDialTimeoutSeconds`
    ///   * `TunnelSshKeepAliveProbeTimeoutSeconds`
    ///   * `TunnelSshKeepAlivePeriodicTimeoutSeconds`
    ///   * `FetchRemoteServerListTimeoutSeconds`
    ///   * `PsiphonApiServerTimeoutSeconds`
    ///   * `FetchRoutesTimeoutSeconds`
    ///   * `HttpProxyOriginServerTimeoutSeconds`
    ///
    /// **All other config fields must not be set.**
    ///
    /// See the [tunnel-core config code](https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/master/psiphon/config.go) for details about the fields.
    ///
    /// - returns: JSON string with config that should used to run the Psiphon tunnel, or nil on error.
    func getPsiphonConfig() -> String?
    
    /// Gets runtime errors info that may be useful for debugging.
    /// - parameters:
    ///   - message: The diagnostic message string.
    func onDiagnosticMessage(_ message: String)
    
    /// Called when the tunnel is in the process of connecting.
    func onConnecting()
    /// Called when the tunnel has successfully connected.
    func onConnected()
    
    /// Called to indicate that tunnel-core is exiting imminently (usually do to
    /// a `stop()` call, but could be due to an unexpected error).
    func onExiting()
    
    /// Called when tunnel-core determines which server egress regions are available
    /// for use. This can be used for updating the UI which provides the options to
    /// the user.
    /// - parameters:
    ///   - regions: A string array containing the available egress region country codes.
    func onAvailableEgressRegions(regions: [String])
    
    /// If the tunnel is started with a fixed SOCKS proxy port, and that port is
    /// already in use, this will be called.
    /// - parameters:
    ///   - port: The port number.
    func onSocksProxyPortInUse(port: Int)
    /// If the tunnel is started with a fixed HTTP proxy port, and that port is
    /// already in use, this will be called.
    /// - parameters:
    ///   - port: The port number.
    func onHttpProxyPortInUse(port: Int)
    
    /// Called when tunnel-core determines what port will be used for the local
    /// SOCKS proxy.
    /// - parameters:
    ///   - port: The port number.
    func onListeningSocksProxyPort(port: Int)
    /// Called when tunnel-core determines what port will be used for the local
    /// HTTP proxy.
    /// - parameters:
    ///   - port: The port number.
    func onListeningHttpProxyPort(port: Int)
    
    /// Called when a error occurs when trying to utilize a configured upstream proxy.
    /// - parameters:
    ///   - message: A message giving additional info about the error.
    func onUpstreamProxyError(message: String)
    
    // TODO: Only applicable to Psiphon proper?
    /// Called when a client upgrade has been downloaded.
    /// - parameters:
    ///   - filename: The name of the file containing the upgrade.
    func onClientUpgradeDownloaded(filename: String)
    
    // TODO: Only applicable to Psiphon proper?
    /// Called if the current version of the client is the latest (i.e., there is no upgrade available).
    func onClientIsLatestVersion()
    
    // TODO: Only applicable to Psiphon proper?
    /// Called when tunnel-core discovers a home page associated with this client.
    /// If there are no home pages, it will not be called. May be called more than
    /// once, for multiple home pages.
    /// - parameters:
    ///   - url: The URL of the home page.
    func onHomepage(url: String)
    
    /// Called after the handshake with the Psiphon server, with the client region 
    /// as determined by the server.
    /// - parameters:
    ///   - region: The country code of the client, as determined by the server.
    func onClientRegion(region: String)
    
    /// Called to report that split tunnel is on for the given region.
    /// - parameters:
    ///   - region: The region split tunnel is on for.
    func onSplitTunnelRegion(region: String)
 
    /// Called to indicate that an address has been classified as being within the
    /// split tunnel region and therefore is being access directly rather than
    /// tunneled.
    /// Note: `address` should remain private; this notice should be used for alerting
    /// users, not for diagnotics logs.
    /// - parameters:
    ///   - address: The IP or hostname that is not being tunneled.
    func onUntunneledAddress(address: String)
    
    /// Called to report how many bytes have been transferred since the last time
    /// this function was called.
    /// - parameters:
    ///   - sent: The number of bytes sent.
    ///   - received: The number of bytes received.
    func onBytesTransferred(sent: Int64, received: Int64)
    
    // TODO: Applies to iOS?
    //func onClientVerificationRequired(nonce: String, ttlSeconds: Int, resetCache: Bool)
}

public enum PsiphonTunnelError : Error {
    /// Thrown when caller tries to access unsupported functionality.
    case UnsupportedError(String)
    /// Thrown when an invalid configuration value is detected.
    case InvalidConfig(String)
    /// Thrown when a system error occurs.
    case SystemError(String)
    /// Thrown when a weak reference has changed to nil. This generally indicates that something was called (which shouldn't have been) during shutdown.
    case WeakRefLost
}

public class PsiphonTunnel: Psi.GoPsiPsiphonProvider {
    private weak var tunneledAppDelegate: TunneledAppDelegate?
    
    // TODO: Review use of this for synchronization.
    private static let serialQueue = DispatchQueue(label: "com.psiphon3.library.PsiphonTunnel")
    
    // TODO: This may not be necessary for iOS.
    private let localSocksProxyPort = AtomicInt()
    
    // Only one PsiphonVpn instance may exist at a time, as the underlying
    // go.psi.Psi and tun2socks implementations each contain global state.
    static private var psiphonTunnel: PsiphonTunnel?
    
    //--------------------------------------------------------------------------
    // Public API
    //--------------------------------------------------------------------------
    
    /// Returns an instance of PsiphonTunnel. This is either a new instance or the pre-existing singleton. If an instance already exists, it will be stopped when this function is called.
    /// - parameters:
    ///   - tunneledAppDelegate: The delegate implementation to use for callbacks.
    /// - returns: The PsiphonTunnel instance.
    public static func newPsiphonTunnel(tunneledAppDelegate: TunneledAppDelegate) -> PsiphonTunnel {
        // Create a new instance.
        let newTunnel = PsiphonTunnel()
        
        // Do the following work in the class mutex, as it modifies the static singleton member.
        PsiphonTunnel.serialQueue.sync {
            // If there's already an instance, stop it.
            PsiphonTunnel.psiphonTunnel?.stop()
        
            // Use the new instance as the singleton.
            PsiphonTunnel.psiphonTunnel = newTunnel
            PsiphonTunnel.psiphonTunnel?.tunneledAppDelegate = tunneledAppDelegate
        }
        
        return newTunnel
    }
    
    /// Start connecting the PsiphonTunnel. Returns before connection is complete -- delegate callbacks (such as `onConnected()`) are used to indicate progress and state.
    /// - parameters:
    ///   - embeddedServerEntries: Pre-existing server entries to use when attempting to connect to a server.
    /// - throws: `PsiphonTunnelError`.
    public func start(embeddedServerEntries: String) throws {
        try PsiphonTunnel.serialQueue.sync {
            try startPsiphon(embeddedServerEntries: embeddedServerEntries)
        }
    }
    
    /// Stop the tunnel (regardless of its current connection state). Returns before full stop is complete -- `TunneledAppDelegate.onExiting()` is called when complete.
    public func stop() {
        PsiphonTunnel.serialQueue.sync {
            stopPsiphon()
            localSocksProxyPort.set(0)
        }
    }
    
    //--------------------------------------------------------------------------
    // Psiphon Tunnel Core
    //--------------------------------------------------------------------------
    
    private func startPsiphon(embeddedServerEntries: String) throws {
        // TODO: Param? If allowed for iOS.
        let useDeviceBinder = false
        
        let config = try getConfig()
        
        var err: NSError?
        let res = Psi.GoPsiStart(config, embeddedServerEntries, self, useDeviceBinder, &err)
        tunneledAppDelegate?.onDiagnosticMessage("Psi.GoPsiStart: \(res.description)")
        if !res && err != nil {
            tunneledAppDelegate?.onDiagnosticMessage("Psi.GoPsiStart error: \(err!.localizedDescription)")
        }
    }
    
    private func stopPsiphon() {
        tunneledAppDelegate?.onDiagnosticMessage("stopping Psiphon library")
        Psi.GoPsiStop()
        tunneledAppDelegate?.onDiagnosticMessage("Psiphon library stopped")
    }
    
    /// Creates the config string that should be passed to tunnel core.
    private func getConfig() throws -> String {
        // tunneledAppDelegate is a weak reference, so check it.
        guard self.tunneledAppDelegate != nil else {
            tunneledAppDelegate?.onDiagnosticMessage("tunneledApp delegate lost")
            throw PsiphonTunnelError.WeakRefLost
        }

        guard let baseConfigString = self.tunneledAppDelegate?.getPsiphonConfig() else {
            tunneledAppDelegate?.onDiagnosticMessage("Error getting config from delegate")
            throw PsiphonTunnelError.InvalidConfig("nil returned by getPsiphonConfig()")
        }
        
        guard let baseConfigData = baseConfigString.data(using: String.Encoding.utf8) else {
            tunneledAppDelegate?.onDiagnosticMessage("Config not properly UTF-8 encoded")
            throw PsiphonTunnelError.InvalidConfig("Config not properly UTF-8 encoded")
        }
        
        var config = JSON(data: baseConfigData)
        
        //
        // Check for required values
        //
        
        guard (config["PropagationChannelId"].string != nil) else {
            tunneledAppDelegate?.onDiagnosticMessage("Config missing PropagationChannelId: \(config["PropagationChannelId"].error)")
            throw PsiphonTunnelError.InvalidConfig(config["PropagationChannelId"].error!.localizedDescription)
        }
        
        guard (config["SponsorId"].string != nil) else {
            tunneledAppDelegate?.onDiagnosticMessage("Config missing SponsorId: \(config["SponsorId"].error)")
            throw PsiphonTunnelError.InvalidConfig(config["SponsorId"].error!.localizedDescription)
        }
        
        //
        // Fill in optional config values.
        //
        
        let libraryURL: URL
        do {
            libraryURL = try FileManager.default.url(for: .libraryDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        } catch {
            tunneledAppDelegate?.onDiagnosticMessage("Unable to get Library URL: \(error.localizedDescription)")
            throw PsiphonTunnelError.SystemError("Unable to get Library URL")
        }
        
        // Some clients will have a data directory that they'd prefer the Psiphon
        // library use, but if not we'll default to the user Library directory.
        let defaultDataStoreDirectoryURL = libraryURL.appendingPathComponent("datastore", isDirectory: true)
        
        if config["DataStoreDirectory"].string == nil {
            do {
                try FileManager.default.createDirectory(at: defaultDataStoreDirectoryURL, withIntermediateDirectories: true)
            } catch {
                tunneledAppDelegate?.onDiagnosticMessage("Unable to create default datastore directory: \(error.localizedDescription)")
                throw PsiphonTunnelError.SystemError("Unable to create default datastore directory")
            }
            
            config["DataStoreDirectory"].string = defaultDataStoreDirectoryURL.path
        } else {
            tunneledAppDelegate?.onDiagnosticMessage("DataStoreDirectory overridden from '\(defaultDataStoreDirectoryURL.path)' to '\(config["DataStoreDirectory"].stringValue)'")
        }
        
        // See previous comment.
        let defaultRemoteServerListFilename = libraryURL.appendingPathComponent("remote_server_list", isDirectory: false).path
        if config["RemoteServerListDownloadFilename"].string == nil {
            config["RemoteServerListDownloadFilename"].string = defaultRemoteServerListFilename
        } else {
            tunneledAppDelegate?.onDiagnosticMessage("RemoteServerListDownloadFilename overridden from '\(defaultRemoteServerListFilename)' to '\(config["RemoteServerListDownloadFilename"].stringValue)'")
        }
        
        // If RemoteServerListUrl and RemoteServerListSignaturePublicKey are absent,
        // we'll just leave them out, but we'll log about it.
        if config["RemoteServerListUrl"].string == nil || config["RemoteServerListSignaturePublicKey"].string == nil {
            tunneledAppDelegate?.onDiagnosticMessage("Remote server list functionality will be disabled")
        }
        
        // Default is to try to connect indefinitely.
        if config["EstablishTunnelTimeoutSeconds"].int == nil {
            config["EstablishTunnelTimeoutSeconds"].int = 0
        }
        
        // For stats purposes (and probably only 1 for Psiphon proper).
        if config["TunnelWholeDevice"].int == nil {
            config["TunnelWholeDevice"].int = 0
        }
        
        if localSocksProxyPort.get() != 0 &&
           (config["LocalSocksProxyPort"].int == nil || config["LocalSocksProxyPort"].int! == 0) {
            // TODO: Is this relevant for iOS?
            // When localSocksProxyPort is set, tun2socks is already configured
            // to use that port value. So we force use of the same port.
            // A side-effect of this is that changing the SOCKS port preference
            // has no effect with restartPsiphon(), a full stop() is necessary.
            config["LocalSocksProxyPort"].int = localSocksProxyPort.get()
        }
        
        // Other optional fields not being altered:
        // * LocalSocksProxyPort
        // * LocalHttpProxyPort
        // * UpstreamProxyUrl
        // * EmitDiagnosticNotices
        // * EgressRegion
        // * UpgradeDownloadUrl
        // * UpgradeDownloadClientVersionHeader
        // * UpgradeDownloadFilename
        // * timeout fields
        
        //
        // Fill in the rest of the values.
        //
        
        // TODO: Should be configurable?
        config["EmitBytesTransferred"].bool = true
        
        config["DeviceRegion"].string = PsiphonTunnel.getDeviceRegion()
        
        config["UseIndistinguishableTLS"].bool = false
        
        let bundledTrustedCAPath = Bundle.main.url(forResource: "rootCAs", withExtension: "txt")?.path
        if bundledTrustedCAPath == nil || !FileManager.default.fileExists(atPath: bundledTrustedCAPath!) {
            tunneledAppDelegate?.onDiagnosticMessage("Unable to find Root CAs file in bundle")
            throw PsiphonTunnelError.SystemError("Unable to find Root CAs file in bundle")
        }
        config["TrustedCACertificatesFilename"].string = bundledTrustedCAPath

        //
        // Many other fields must *only* be modified by official Psiphon clients.
        // Some of them require default values.
        //
        
        // TODO: After updating tunnel-core in the framework, verify that this value is getting through to Kibana.
        if config["ClientPlatform"].string == nil {
            config["ClientPlatform"].string = "iOS-Library"
        } else {
            tunneledAppDelegate?.onDiagnosticMessage("ClientPlatform overridden from 'iOS-Library' to '\(config["ClientPlatform"].stringValue)'")
        }
        
        let finalConfigJson = config.rawString()
        return finalConfigJson!
    }
    
    private func handlePsiphonNotice(noticeJSON: String) {
        // All notices are sent on as diagnostic messages except those that may
        // contain private user data.
        var diagnostic = true
        
        guard let noticeJSONData = noticeJSON.data(using: String.Encoding.utf8) else {
            tunneledAppDelegate?.onDiagnosticMessage("Unable to decode noticeJSON")
            return
        }
        
        var notice = JSON(data: noticeJSONData)
        
        guard let noticeType = notice["noticeType"].string else {
            tunneledAppDelegate?.onDiagnosticMessage("Notice missing noticeType: \(notice["noticeType"].error)")
            return
        }
        
        switch(noticeType) {
        case "Tunnels":
            guard let count = notice["data"]["count"].int else {
                tunneledAppDelegate?.onDiagnosticMessage("Tunnels Notice count invalid: \(notice["data"]["count"].error)")
                return
            }
            
            if count > 0 {
                // TODO: if isVpnMode() { routeThroughTunnel() }
                tunneledAppDelegate?.onConnected()
            } else {
                tunneledAppDelegate?.onConnecting()
            }
            
        case "Exiting":
            tunneledAppDelegate?.onExiting()
            
        case "AvailableEgressRegions":
            guard let regionsArray = notice["data"]["regions"].array else {
                tunneledAppDelegate?.onDiagnosticMessage("AvailableEgressRegions Notice missing regions: \(notice["data"]["regions"].error)")
                return
            }
            
            var regions = [String]()

            for obj in regionsArray {
                guard let region = obj.string else {
                    tunneledAppDelegate?.onDiagnosticMessage("Item in regions array is not a string: \(obj.error)")
                    return
                }
                    
                regions.append(region)
            }

            tunneledAppDelegate?.onAvailableEgressRegions(regions: regions)
            
        case "SocksProxyPortInUse":
            guard let port = notice["data"]["port"].int else {
                tunneledAppDelegate?.onDiagnosticMessage("SocksProxyPortInUse Notice port is invalid: \(notice["data"]["port"].error)")
                return
            }
            tunneledAppDelegate?.onSocksProxyPortInUse(port: port)
            
        case "HttpProxyPortInUse":
            guard let port = notice["data"]["port"].int else {
                tunneledAppDelegate?.onDiagnosticMessage("HttpProxyPortInUse Notice port is invalid: \(notice["data"]["port"].error)")
                return
            }
            tunneledAppDelegate?.onHttpProxyPortInUse(port: port)
            
        case "ListeningSocksProxyPort":
            guard let port = notice["data"]["port"].int else {
                tunneledAppDelegate?.onDiagnosticMessage("ListeningSocksProxyPort Notice port is invalid: \(notice["data"]["port"].error)")
                return
            }
            localSocksProxyPort.set(port)
            tunneledAppDelegate?.onListeningSocksProxyPort(port: port)
            
        case "ListeningHttpProxyPort":
            guard let port = notice["data"]["port"].int else {
                tunneledAppDelegate?.onDiagnosticMessage("ListeningHttpProxyPort Notice port is invalid: \(notice["data"]["port"].error)")
                return
            }
            tunneledAppDelegate?.onListeningHttpProxyPort(port: port)
            
        case "UpstreamProxyError":
            guard let message = notice["data"]["message"].string else {
                tunneledAppDelegate?.onDiagnosticMessage("UpstreamProxyError Notice message is invalid: \(notice["data"]["message"].error)")
                return
            }
            tunneledAppDelegate?.onUpstreamProxyError(message: message)
            
        case "ClientUpgradeDownloaded":
            guard let filename = notice["data"]["filename"].string else {
                tunneledAppDelegate?.onDiagnosticMessage("ClientUpgradeDownloaded Notice filename is invalid: \(notice["data"]["filename"].error)")
                return
            }
            tunneledAppDelegate?.onClientUpgradeDownloaded(filename: filename)
            
        case "ClientIsLatestVersion":
            tunneledAppDelegate?.onClientIsLatestVersion()
            
        case "Homepage":
            guard let url = notice["data"]["url"].string else {
                tunneledAppDelegate?.onDiagnosticMessage("Homepage Notice url is invalid: \(notice["data"]["url"].error)")
                return
            }
            tunneledAppDelegate?.onHomepage(url: url)
            
        case "ClientRegion":
            guard let region = notice["data"]["region"].string else {
                tunneledAppDelegate?.onDiagnosticMessage("ClientRegion Notice region is invalid: \(notice["data"]["region"].error)")
                return
            }
            tunneledAppDelegate?.onClientRegion(region: region)
            
        case "SplitTunnelRegion":
            guard let region = notice["data"]["region"].string else {
                tunneledAppDelegate?.onDiagnosticMessage("SplitTunnelRegion Notice region is invalid: \(notice["data"]["region"].error)")
                return
            }
            tunneledAppDelegate?.onSplitTunnelRegion(region: region)
            
        case "Untunneled":
            guard let address = notice["data"]["address"].string else {
                tunneledAppDelegate?.onDiagnosticMessage("Untunneled Notice address is invalid: \(notice["data"]["address"].error)")
                return
            }
            tunneledAppDelegate?.onUntunneledAddress(address: address)
            
        case "BytesTransferred":
            diagnostic = false
            guard let sent = notice["data"]["sent"].int64 else {
                tunneledAppDelegate?.onDiagnosticMessage("BytesTransferred Notice sent is invalid: \(notice["data"]["sent"].error)")
                return
            }
            guard let received = notice["data"]["received"].int64 else {
                tunneledAppDelegate?.onDiagnosticMessage("BytesTransferred Notice received is invalid: \(notice["data"]["received"].error)")
                return
            }
            tunneledAppDelegate?.onBytesTransferred(sent: sent, received: received)
          
        // TODO: Applies to iOS?
        //case "ClientVerificationRequired":
            
        default: break
        }
        
        if diagnostic {
            if let noticeDataJSON = notice["data"].rawString() {
                tunneledAppDelegate?.onDiagnosticMessage("\(noticeType): \(noticeDataJSON)")
            }
        }
    }
    
    
    
    //--------------------------------------------------------------------------
    // GoPsiPsiphonProvider (Core support) interface implementation (private)
    //--------------------------------------------------------------------------
    
    override public func bind(toDevice fileDescriptor: Int) throws {
        // This PsiphonProvider function is only called in TunnelWholeDevice mode
        throw PsiphonTunnelError.UnsupportedError("BindToDevice not supported")
    }
    
    override public func getPrimaryDnsServer() -> String! {
        // This function is only called when BindToDevice is used/supported.
        return "8.8.8.8"
    }
    
    override public func getSecondaryDnsServer() -> String! {
        // This function is only called when BindToDevice is used/supported.
        return "8.8.4.4"
    }
    
    override public func hasNetworkConnectivity() -> Int {
        // TODO: check actual connectivity state
        return 1
    }
    
    override public func notice(_ noticeJSON: String!) {
        handlePsiphonNotice(noticeJSON: noticeJSON)
    }
    
    //--------------------------------------------------------------------------
    // Helpers
    //--------------------------------------------------------------------------
    
    /// One of the ways we determine the device region is to look at the current timezone. When then need to map that to a likely country.
    /// This mapping is derived from here: https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
    private static let timezoneToCountryCode: [String: String] = ["Africa/Abidjan": "CI", "Africa/Accra": "GH", "Africa/Addis_Ababa": "ET", "Africa/Algiers": "DZ", "Africa/Asmara": "ER", "Africa/Bamako": "ML", "Africa/Bangui": "CF", "Africa/Banjul": "GM", "Africa/Bissau": "GW", "Africa/Blantyre": "MW", "Africa/Brazzaville": "CG", "Africa/Bujumbura": "BI", "Africa/Cairo": "EG", "Africa/Casablanca": "MA", "Africa/Ceuta": "ES", "Africa/Conakry": "GN", "Africa/Dakar": "SN", "Africa/Dar_es_Salaam": "TZ", "Africa/Djibouti": "DJ", "Africa/Douala": "CM", "Africa/El_Aaiun": "EH", "Africa/Freetown": "SL", "Africa/Gaborone": "BW", "Africa/Harare": "ZW", "Africa/Johannesburg": "ZA", "Africa/Juba": "SS", "Africa/Kampala": "UG", "Africa/Khartoum": "SD", "Africa/Kigali": "RW", "Africa/Kinshasa": "CD", "Africa/Lagos": "NG", "Africa/Libreville": "GA", "Africa/Lome": "TG", "Africa/Luanda": "AO", "Africa/Lubumbashi": "CD", "Africa/Lusaka": "ZM", "Africa/Malabo": "GQ", "Africa/Maputo": "MZ", "Africa/Maseru": "LS", "Africa/Mbabane": "SZ", "Africa/Mogadishu": "SO", "Africa/Monrovia": "LR", "Africa/Nairobi": "KE", "Africa/Ndjamena": "TD", "Africa/Niamey": "NE", "Africa/Nouakchott": "MR", "Africa/Ouagadougou": "BF", "Africa/Porto-Novo": "BJ", "Africa/Sao_Tome": "ST", "Africa/Tripoli": "LY", "Africa/Tunis": "TN", "Africa/Windhoek": "NA", "America/Adak": "US", "America/Anchorage": "US", "America/Anguilla": "AI", "America/Antigua": "AG", "America/Araguaina": "BR", "America/Argentina/Buenos_Aires": "AR", "America/Argentina/Catamarca": "AR", "America/Argentina/Cordoba": "AR", "America/Argentina/Jujuy": "AR", "America/Argentina/La_Rioja": "AR", "America/Argentina/Mendoza": "AR", "America/Argentina/Rio_Gallegos": "AR", "America/Argentina/Salta": "AR", "America/Argentina/San_Juan": "AR", "America/Argentina/San_Luis": "AR", "America/Argentina/Tucuman": "AR", "America/Argentina/Ushuaia": "AR", "America/Aruba": "AW", "America/Asuncion": "PY", "America/Atikokan": "CA", "America/Bahia": "BR", "America/Bahia_Banderas": "MX", "America/Barbados": "BB", "America/Belem": "BR", "America/Belize": "BZ", "America/Blanc-Sablon": "CA", "America/Boa_Vista": "BR", "America/Bogota": "CO", "America/Boise": "US", "America/Cambridge_Bay": "CA", "America/Campo_Grande": "BR", "America/Cancun": "MX", "America/Caracas": "VE", "America/Cayenne": "GF", "America/Cayman": "KY", "America/Chicago": "US", "America/Chihuahua": "MX", "America/Costa_Rica": "CR", "America/Creston": "CA", "America/Cuiaba": "BR", "America/Curacao": "CW", "America/Danmarkshavn": "GL", "America/Dawson": "CA", "America/Dawson_Creek": "CA", "America/Denver": "US", "America/Detroit": "US", "America/Dominica": "DM", "America/Edmonton": "CA", "America/Eirunepe": "BR", "America/El_Salvador": "SV", "America/Fort_Nelson": "CA", "America/Fortaleza": "BR", "America/Glace_Bay": "CA", "America/Godthab": "GL", "America/Goose_Bay": "CA", "America/Grand_Turk": "TC", "America/Grenada": "GD", "America/Guadeloupe": "GP", "America/Guatemala": "GT", "America/Guayaquil": "EC", "America/Guyana": "GY", "America/Halifax": "CA", "America/Havana": "CU", "America/Hermosillo": "MX", "America/Indiana/Indianapolis": "US", "America/Indiana/Knox": "US", "America/Indiana/Marengo": "US", "America/Indiana/Petersburg": "US", "America/Indiana/Tell_City": "US", "America/Indiana/Vevay": "US", "America/Indiana/Vincennes": "US", "America/Indiana/Winamac": "US", "America/Inuvik": "CA", "America/Iqaluit": "CA", "America/Jamaica": "JM", "America/Juneau": "US", "America/Kentucky/Louisville": "US", "America/Kentucky/Monticello": "US", "America/Kralendijk": "BQ", "America/La_Paz": "BO", "America/Lima": "PE", "America/Los_Angeles": "US", "America/Lower_Princes": "SX", "America/Maceio": "BR", "America/Managua": "NI", "America/Manaus": "BR", "America/Marigot": "MF", "America/Martinique": "MQ", "America/Matamoros": "MX", "America/Mazatlan": "MX", "America/Menominee": "US", "America/Merida": "MX", "America/Metlakatla": "US", "America/Mexico_City": "MX", "America/Miquelon": "PM", "America/Moncton": "CA", "America/Monterrey": "MX", "America/Montevideo": "UY", "America/Montserrat": "MS", "America/Nassau": "BS", "America/New_York": "US", "America/Nipigon": "CA", "America/Nome": "US", "America/Noronha": "BR", "America/North_Dakota/Beulah": "US", "America/North_Dakota/Center": "US", "America/North_Dakota/New_Salem": "US", "America/Ojinaga": "MX", "America/Panama": "PA", "America/Pangnirtung": "CA", "America/Paramaribo": "SR", "America/Phoenix": "US", "America/Port_of_Spain": "TT", "America/Port-au-Prince": "HT", "America/Porto_Velho": "BR", "America/Puerto_Rico": "PR", "America/Rainy_River": "CA", "America/Rankin_Inlet": "CA", "America/Recife": "BR", "America/Regina": "CA", "America/Resolute": "CA", "America/Rio_Branco": "BR", "America/Santarem": "BR", "America/Santiago": "CL", "America/Santo_Domingo": "DO", "America/Sao_Paulo": "BR", "America/Scoresbysund": "GL", "America/Sitka": "US", "America/St_Barthelemy": "BL", "America/St_Johns": "CA", "America/St_Kitts": "KN", "America/St_Lucia": "LC", "America/St_Thomas": "VI", "America/St_Vincent": "VC", "America/Swift_Current": "CA", "America/Tegucigalpa": "HN", "America/Thule": "GL", "America/Thunder_Bay": "CA", "America/Tijuana": "MX", "America/Toronto": "CA", "America/Tortola": "VG", "America/Vancouver": "CA", "America/Whitehorse": "CA", "America/Winnipeg": "CA", "America/Yakutat": "US", "America/Yellowknife": "CA", "Antarctica/Casey": "AQ", "Antarctica/Davis": "AQ", "Antarctica/DumontDUrville": "AQ", "Antarctica/Macquarie": "AU", "Antarctica/Mawson": "AQ", "Antarctica/McMurdo": "AQ", "Antarctica/Palmer": "AQ", "Antarctica/Rothera": "AQ", "Antarctica/Syowa": "AQ", "Antarctica/Troll": "AQ", "Antarctica/Vostok": "AQ", "Arctic/Longyearbyen": "SJ", "Asia/Aden": "YE", "Asia/Almaty": "KZ", "Asia/Amman": "JO", "Asia/Anadyr": "RU", "Asia/Aqtau": "KZ", "Asia/Aqtobe": "KZ", "Asia/Ashgabat": "TM", "Asia/Baghdad": "IQ", "Asia/Bahrain": "BH", "Asia/Baku": "AZ", "Asia/Bangkok": "TH", "Asia/Barnaul": "RU", "Asia/Beirut": "LB", "Asia/Bishkek": "KG", "Asia/Brunei": "BN", "Asia/Chita": "RU", "Asia/Choibalsan": "MN", "Asia/Colombo": "LK", "Asia/Damascus": "SY", "Asia/Dhaka": "BD", "Asia/Dili": "TL", "Asia/Dubai": "AE", "Asia/Dushanbe": "TJ", "Asia/Gaza": "PS", "Asia/Hebron": "PS", "Asia/Ho_Chi_Minh": "VN", "Asia/Hong_Kong": "HK", "Asia/Hovd": "MN", "Asia/Irkutsk": "RU", "Asia/Jakarta": "ID", "Asia/Jayapura": "ID", "Asia/Jerusalem": "IL", "Asia/Kabul": "AF", "Asia/Kamchatka": "RU", "Asia/Karachi": "PK", "Asia/Kathmandu": "NP", "Asia/Khandyga": "RU", "Asia/Kolkata": "IN", "Asia/Krasnoyarsk": "RU", "Asia/Kuala_Lumpur": "MY", "Asia/Kuching": "MY", "Asia/Kuwait": "KW", "Asia/Macau": "MO", "Asia/Magadan": "RU", "Asia/Makassar": "ID", "Asia/Manila": "PH", "Asia/Muscat": "OM", "Asia/Nicosia": "CY", "Asia/Novokuznetsk": "RU", "Asia/Novosibirsk": "RU", "Asia/Omsk": "RU", "Asia/Oral": "KZ", "Asia/Phnom_Penh": "KH", "Asia/Pontianak": "ID", "Asia/Pyongyang": "KP", "Asia/Qatar": "QA", "Asia/Qyzylorda": "KZ", "Asia/Rangoon": "MM", "Asia/Riyadh": "SA", "Asia/Sakhalin": "RU", "Asia/Samarkand": "UZ", "Asia/Seoul": "KR", "Asia/Shanghai": "CN", "Asia/Singapore": "SG", "Asia/Srednekolymsk": "RU", "Asia/Taipei": "TW", "Asia/Tashkent": "UZ", "Asia/Tbilisi": "GE", "Asia/Tehran": "IR", "Asia/Thimphu": "BT", "Asia/Tokyo": "JP", "Asia/Tomsk": "RU", "Asia/Ulaanbaatar": "MN", "Asia/Urumqi": "CN", "Asia/Ust-Nera": "RU", "Asia/Vientiane": "LA", "Asia/Vladivostok": "RU", "Asia/Yakutsk": "RU", "Asia/Yekaterinburg": "RU", "Asia/Yerevan": "AM", "Atlantic/Azores": "PT", "Atlantic/Bermuda": "BM", "Atlantic/Canary": "ES", "Atlantic/Cape_Verde": "CV", "Atlantic/Faroe": "FO", "Atlantic/Madeira": "PT", "Atlantic/Reykjavik": "IS", "Atlantic/South_Georgia": "GS", "Atlantic/St_Helena": "SH", "Atlantic/Stanley": "FK", "Australia/Adelaide": "AU", "Australia/Brisbane": "AU", "Australia/Broken_Hill": "AU", "Australia/Currie": "AU", "Australia/Darwin": "AU", "Australia/Eucla": "AU", "Australia/Hobart": "AU", "Australia/Lindeman": "AU", "Australia/Lord_Howe": "AU", "Australia/Melbourne": "AU", "Australia/Perth": "AU", "Australia/Sydney": "AU", "Europe/Amsterdam": "NL", "Europe/Andorra": "AD", "Europe/Astrakhan": "RU", "Europe/Athens": "GR", "Europe/Belgrade": "RS", "Europe/Berlin": "DE", "Europe/Bratislava": "SK", "Europe/Brussels": "BE", "Europe/Bucharest": "RO", "Europe/Budapest": "HU", "Europe/Busingen": "DE", "Europe/Chisinau": "MD", "Europe/Copenhagen": "DK", "Europe/Dublin": "IE", "Europe/Gibraltar": "GI", "Europe/Guernsey": "GG", "Europe/Helsinki": "FI", "Europe/Isle_of_Man": "IM", "Europe/Istanbul": "TR", "Europe/Jersey": "JE", "Europe/Kaliningrad": "RU", "Europe/Kiev": "UA", "Europe/Kirov": "RU", "Europe/Lisbon": "PT", "Europe/Ljubljana": "SI", "Europe/London": "GB", "Europe/Luxembourg": "LU", "Europe/Madrid": "ES", "Europe/Malta": "MT", "Europe/Mariehamn": "AX", "Europe/Minsk": "BY", "Europe/Monaco": "MC", "Europe/Moscow": "RU", "Europe/Oslo": "NO", "Europe/Paris": "FR", "Europe/Podgorica": "ME", "Europe/Prague": "CZ", "Europe/Riga": "LV", "Europe/Rome": "IT", "Europe/Samara": "RU", "Europe/San_Marino": "SM", "Europe/Sarajevo": "BA", "Europe/Simferopol": "RU", "Europe/Skopje": "MK", "Europe/Sofia": "BG", "Europe/Stockholm": "SE", "Europe/Tallinn": "EE", "Europe/Tirane": "AL", "Europe/Ulyanovsk": "RU", "Europe/Uzhgorod": "UA", "Europe/Vaduz": "LI", "Europe/Vatican": "VA", "Europe/Vienna": "AT", "Europe/Vilnius": "LT", "Europe/Volgograd": "RU", "Europe/Warsaw": "PL", "Europe/Zagreb": "HR", "Europe/Zaporozhye": "UA", "Europe/Zurich": "CH", "Indian/Antananarivo": "MG", "Indian/Chagos": "IO", "Indian/Christmas": "CX", "Indian/Cocos": "CC", "Indian/Comoro": "KM", "Indian/Kerguelen": "TF", "Indian/Mahe": "SC", "Indian/Maldives": "MV", "Indian/Mauritius": "MU", "Indian/Mayotte": "YT", "Indian/Reunion": "RE", "Pacific/Apia": "WS", "Pacific/Auckland": "NZ", "Pacific/Bougainville": "PG", "Pacific/Chatham": "NZ", "Pacific/Chuuk": "FM", "Pacific/Easter": "CL", "Pacific/Efate": "VU", "Pacific/Enderbury": "KI", "Pacific/Fakaofo": "TK", "Pacific/Fiji": "FJ", "Pacific/Funafuti": "TV", "Pacific/Galapagos": "EC", "Pacific/Gambier": "PF", "Pacific/Guadalcanal": "SB", "Pacific/Guam": "GU", "Pacific/Honolulu": "US", "Pacific/Johnston": "UM", "Pacific/Kiritimati": "KI", "Pacific/Kosrae": "FM", "Pacific/Kwajalein": "MH", "Pacific/Majuro": "MH", "Pacific/Marquesas": "PF", "Pacific/Midway": "UM", "Pacific/Nauru": "NR", "Pacific/Niue": "NU", "Pacific/Norfolk": "NF", "Pacific/Noumea": "NC", "Pacific/Pago_Pago": "AS", "Pacific/Palau": "PW", "Pacific/Pitcairn": "PN", "Pacific/Pohnpei": "FM", "Pacific/Port_Moresby": "PG", "Pacific/Rarotonga": "CK", "Pacific/Saipan": "MP", "Pacific/Tahiti": "PF", "Pacific/Tarawa": "KI", "Pacific/Tongatapu": "TO", "Pacific/Wake": "UM", "Pacific/Wallis": "WF"]
    
    /// Determine the device's region. Makes a best guess based on available info.
    /// - returns: The two-letter country code that the device is probably located in.
    static func getDeviceRegion() -> String {
        // First try getting from telephony info (will fail for non-phones and simulator)
        let networkInfo = CTTelephonyNetworkInfo()
        let carrier = networkInfo.subscriberCellularProvider
        let carrierCountryCode = carrier?.isoCountryCode
        
        if carrierCountryCode != nil {
            return carrierCountryCode!
        }
        
        // Next try to map the time zone to a country code.
        let timezone = NSTimeZone.local.identifier
        if let timezoneCountryCode = timezoneToCountryCode[timezone] {
            return timezoneCountryCode
        }
        
        // Next try getting the region from the current locale. This isn't
        // terribly reliable (because, for example, en-US is used in a lot of
        // places that aren't the US).
        let localeCountryCode = NSLocale.current.regionCode
        
        if localeCountryCode != nil {
            return localeCountryCode!
        }
        
        // Generic-ish default
        return "US"
    }
}

// TODO: Review the thread-safety and performance of this.
private class AtomicInt {
    let serialQueue = DispatchQueue(label: "com.psiphon3.library.AtomicInt")
    
    private var value : Int = 0
    
    func get() -> Int {
        var v: Int = 0
        serialQueue.sync {
            v = value
        }
        
        return v
    }

    func set(_ newValue: Int) {
        serialQueue.sync {
            value = newValue
        }
    }
}
