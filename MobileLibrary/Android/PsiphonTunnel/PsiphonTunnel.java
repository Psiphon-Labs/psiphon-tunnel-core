/*
 * Copyright (c) 2015, Psiphon Inc.
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

package ca.psiphon;

import android.annotation.TargetApi;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiInfo;
import android.net.LinkProperties;
import android.net.NetworkInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.telephony.TelephonyManager;
import android.util.Base64;

import org.apache.http.conn.util.InetAddressUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import psi.Psi;
import psi.PsiphonProvider;

public class PsiphonTunnel implements PsiphonProvider {

    public interface HostService {
        public String getAppName();
        public Context getContext();
        public Object getVpnService(); // Object must be a VpnService (Android < 4 cannot reference this class name)
        public Object newVpnServiceBuilder(); // Object must be a VpnService.Builder (Android < 4 cannot reference this class name)
        public String getPsiphonConfig();
        public void onDiagnosticMessage(String message);
        public void onAvailableEgressRegions(List<String> regions);
        public void onSocksProxyPortInUse(int port);
        public void onHttpProxyPortInUse(int port);
        public void onListeningSocksProxyPort(int port);
        public void onListeningHttpProxyPort(int port);
        public void onUpstreamProxyError(String message);
        public void onConnecting();
        public void onConnected();
        public void onHomepage(String url);
        public void onClientRegion(String region);
        public void onClientUpgradeDownloaded(String filename);
        public void onClientIsLatestVersion();
        public void onSplitTunnelRegion(String region);
        public void onUntunneledAddress(String address);
        public void onBytesTransferred(long sent, long received);
        public void onStartedWaitingForNetworkConnectivity();
        public void onActiveAuthorizationIDs(List<String> authorizations);
        public void onExiting();
    }

    private final HostService mHostService;
    private AtomicBoolean mVpnMode;
    private PrivateAddress mPrivateAddress;
    private AtomicReference<ParcelFileDescriptor> mTunFd;
    private AtomicInteger mLocalSocksProxyPort;
    private AtomicBoolean mRoutingThroughTunnel;
    private Thread mTun2SocksThread;
    private AtomicBoolean mIsWaitingForNetworkConnectivity;
    private AtomicReference<String> mClientPlatformPrefix;
    private AtomicReference<String> mClientPlatformSuffix;

    // mUsePacketTunnel specifies whether to use the packet
    // tunnel instead of tun2socks; currently this is for
    // testing only and is disabled.
    private boolean mUsePacketTunnel = false;

    // Only one PsiphonVpn instance may exist at a time, as the underlying
    // psi.Psi and tun2socks implementations each contain global state.
    private static PsiphonTunnel mPsiphonTunnel;

    public static synchronized PsiphonTunnel newPsiphonTunnel(HostService hostService) {
        if (mPsiphonTunnel != null) {
            mPsiphonTunnel.stop();
        }
        // Load the native go code embedded in psi.aar
        System.loadLibrary("gojni");
        mPsiphonTunnel = new PsiphonTunnel(hostService);
        return mPsiphonTunnel;
    }

    private PsiphonTunnel(HostService hostService) {
        mHostService = hostService;
        mVpnMode = new AtomicBoolean(false);
        mTunFd = new AtomicReference<ParcelFileDescriptor>();
        mLocalSocksProxyPort = new AtomicInteger(0);
        mRoutingThroughTunnel = new AtomicBoolean(false);
        mIsWaitingForNetworkConnectivity = new AtomicBoolean(false);
        mClientPlatformPrefix = new AtomicReference<String>("");
        mClientPlatformSuffix = new AtomicReference<String>("");
    }

    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    //----------------------------------------------------------------------------------------------
    // Public API
    //----------------------------------------------------------------------------------------------

    // To start, call in sequence: startRouting(), then startTunneling(). After startRouting()
    // succeeds, the caller must call stop() to clean up. These functions should not be called
    // concurrently. Do not call stop() while startRouting() or startTunneling() is in progress.

    // Returns true when the VPN routing is established; returns false if the VPN could not
    // be started due to lack of prepare or revoked permissions (called should re-prepare and
    // try again); throws exception for other error conditions.
    public synchronized boolean startRouting() throws Exception {

        // Note: tun2socks is loaded even in mUsePacketTunnel mode,
        // as disableUdpGwKeepalive will still be called.

        // Load tun2socks library embedded in the aar
        // If this method is called more than once with the same library name, the second and subsequent calls are ignored.
        // http://docs.oracle.com/javase/7/docs/api/java/lang/Runtime.html#loadLibrary%28java.lang.String%29
        System.loadLibrary("tun2socks");
        return startVpn();
    }

    // Throws an exception in error conditions. In the case of an exception, the routing
    // started by startRouting() is not immediately torn down (this allows the caller to control
    // exactly when VPN routing is stopped); caller should call stop() to clean up.
    public synchronized void startTunneling(String embeddedServerEntries) throws Exception {
        startPsiphon(embeddedServerEntries);
    }

    // Note: to avoid deadlock, do not call directly from a HostService callback;
    // instead post to a Handler if necessary to trigger from a HostService callback.
    // For example, deadlock can occur when a Notice callback invokes stop() since stop() calls
    // Psi.stop() which will block waiting for tunnel-core Controller to shutdown which in turn
    // waits for Notice callback invoker to stop, meanwhile the callback thread has blocked waiting
    // for stop().
    public synchronized void stop() {
        stopVpn();
        stopPsiphon();
        mVpnMode.set(false);
        mLocalSocksProxyPort.set(0);
    }

    // Note: same deadlock note as stop().
    public synchronized void restartPsiphon() throws Exception {
        stopPsiphon();
        startPsiphon("");
    }

    public void setClientPlatformAffixes(String prefix, String suffix) {
        mClientPlatformPrefix.set(prefix);
        mClientPlatformSuffix.set(suffix);
    }

    public String exportExchangePayload() {
        return Psi.exportExchangePayload();
    }

    public boolean importExchangePayload(String payload) {
        return Psi.importExchangePayload(payload);
    }

    // Writes Go runtime profile information to a set of files in the specifiec output directory.
    // cpuSampleDurationSeconds and blockSampleDurationSeconds determines how to long to wait and
    // sample profiles that require active sampling. When set to 0, these profiles are skipped.
    public void writeRuntimeProfiles(String outputDirectory, int cpuSampleDurationSeconnds, int blockSampleDurationSeconds) {
        Psi.writeRuntimeProfiles(outputDirectory, cpuSampleDurationSeconnds, blockSampleDurationSeconds);
    }

    //----------------------------------------------------------------------------------------------
    // VPN Routing
    //----------------------------------------------------------------------------------------------

    private final static String VPN_INTERFACE_NETMASK = "255.255.255.0";
    private final static int VPN_INTERFACE_MTU = 1500;
    private final static int UDPGW_SERVER_PORT = 7300;
    private final static String DEFAULT_PRIMARY_DNS_SERVER = "8.8.4.4";
    private final static String DEFAULT_SECONDARY_DNS_SERVER = "8.8.8.8";

    // Note: Atomic variables used for getting/setting local proxy port, routing flag, and
    // tun fd, as these functions may be called via PsiphonProvider callbacks. Do not use
    // synchronized functions as stop() is synchronized and a deadlock is possible as callbacks
    // can be called while stop holds the lock.

    @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    private boolean startVpn() throws Exception {

        mVpnMode.set(true);
        mPrivateAddress = selectPrivateAddress();

        Locale previousLocale = Locale.getDefault();

        final String errorMessage = "startVpn failed";
        try {
            // Workaround for https://code.google.com/p/android/issues/detail?id=61096
            Locale.setDefault(new Locale("en"));

            int mtu = VPN_INTERFACE_MTU;
            String dnsResolver = mPrivateAddress.mRouter;

            if (mUsePacketTunnel) {
                mtu = (int)Psi.getPacketTunnelMTU();
                dnsResolver = Psi.getPacketTunnelDNSResolverIPv4Address();
            }

            ParcelFileDescriptor tunFd =
                    ((VpnService.Builder) mHostService.newVpnServiceBuilder())
                            .setSession(mHostService.getAppName())
                            .setMtu(mtu)
                            .addAddress(mPrivateAddress.mIpAddress, mPrivateAddress.mPrefixLength)
                            .addRoute("0.0.0.0", 0)
                            .addRoute(mPrivateAddress.mSubnet, mPrivateAddress.mPrefixLength)
                            .addDnsServer(dnsResolver)
                            .establish();
            if (tunFd == null) {
                // As per http://developer.android.com/reference/android/net/VpnService.Builder.html#establish%28%29,
                // this application is no longer prepared or was revoked.
                return false;
            }
            mTunFd.set(tunFd);
            mRoutingThroughTunnel.set(false);

            mHostService.onDiagnosticMessage("VPN established");

        } catch(IllegalArgumentException e) {
            throw new Exception(errorMessage, e);
        } catch(IllegalStateException e) {
            throw new Exception(errorMessage, e);
        } catch(SecurityException e) {
            throw new Exception(errorMessage, e);
        } finally {
            // Restore the original locale.
            Locale.setDefault(previousLocale);
        }

        return true;
    }

    private boolean isVpnMode() {
        return mVpnMode.get();
    }

    private void setLocalSocksProxyPort(int port) {
        mLocalSocksProxyPort.set(port);
    }

    private void routeThroughTunnel() {
        if (!mRoutingThroughTunnel.compareAndSet(false, true)) {
            return;
        }

        if (!mUsePacketTunnel) {
            ParcelFileDescriptor tunFd = mTunFd.getAndSet(null);
            if (tunFd == null) {
                return;
            }
            String socksServerAddress = "127.0.0.1:" + Integer.toString(mLocalSocksProxyPort.get());
            String udpgwServerAddress = "127.0.0.1:" + Integer.toString(UDPGW_SERVER_PORT);
            startTun2Socks(
                    tunFd,
                    VPN_INTERFACE_MTU,
                    mPrivateAddress.mRouter,
                    VPN_INTERFACE_NETMASK,
                    socksServerAddress,
                    udpgwServerAddress,
                    true);
        }

        mHostService.onDiagnosticMessage("routing through tunnel");

        // TODO: should double-check tunnel routing; see:
        // https://bitbucket.org/psiphon/psiphon-circumvention-system/src/1dc5e4257dca99790109f3bf374e8ab3a0ead4d7/Android/PsiphonAndroidLibrary/src/com/psiphon3/psiphonlibrary/TunnelCore.java?at=default#cl-779
    }

    private void stopVpn() {

        if (!mUsePacketTunnel) {
            stopTun2Socks();
        }

        ParcelFileDescriptor tunFd = mTunFd.getAndSet(null);
        if (tunFd != null) {
            try {
                tunFd.close();
            } catch (IOException e) {
            }
        }
        mRoutingThroughTunnel.set(false);
    }

    //----------------------------------------------------------------------------------------------
    // PsiphonProvider (Core support) interface implementation
    //----------------------------------------------------------------------------------------------

    @Override
    public void notice(String noticeJSON) {
        handlePsiphonNotice(noticeJSON);
    }

    @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    @Override
    public String bindToDevice(long fileDescriptor) throws Exception {
        if (!((VpnService)mHostService.getVpnService()).protect((int)fileDescriptor)) {
            throw new Exception("protect socket failed");
        }
        return "";
    }

    @Override
    public long hasNetworkConnectivity() {
        boolean hasConnectivity = hasNetworkConnectivity(mHostService.getContext());
        boolean wasWaitingForNetworkConnectivity = mIsWaitingForNetworkConnectivity.getAndSet(!hasConnectivity);
        if (!hasConnectivity && !wasWaitingForNetworkConnectivity) {
            // HasNetworkConnectivity may be called many times, but only call
            // onStartedWaitingForNetworkConnectivity once per loss of connectivity,
            // so the HostService may log a single message.
            mHostService.onStartedWaitingForNetworkConnectivity();
        }
        // TODO: change to bool return value once gobind supports that type
        return hasConnectivity ? 1 : 0;
    }

    @Override
    public String getPrimaryDnsServer() {
        String dnsResolver = null;
        try {
            dnsResolver = getFirstActiveNetworkDnsResolver(mHostService.getContext());
        } catch (Exception e) {
            mHostService.onDiagnosticMessage("failed to get active network DNS resolver: " + e.getMessage());
            dnsResolver = DEFAULT_PRIMARY_DNS_SERVER;
        }
        return dnsResolver;
    }

    @Override
    public String getSecondaryDnsServer() {
        return DEFAULT_SECONDARY_DNS_SERVER;
    }

    @Override
    public String iPv6Synthesize(String IPv4Addr) { return IPv4Addr; }

    @Override
    public String getNetworkID() {

        // The network ID contains potential PII. In tunnel-core, the network ID
        // is used only locally in the client and not sent to the server.
        //
        // See network ID requirements here:
        // https://godoc.org/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon#NetworkIDGetter

        String networkID = "UNKNOWN";

        Context context = mHostService.getContext();
        ConnectivityManager connectivityManager = (ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo activeNetworkInfo = null;
        try {
            activeNetworkInfo = connectivityManager.getActiveNetworkInfo();

        } catch (java.lang.Exception e) {
            // May get exceptions due to missing permissions like android.permission.ACCESS_NETWORK_STATE.

            // Apps using the Psiphon Library and lacking android.permission.ACCESS_NETWORK_STATE will
            // proceed and use tactics, but with "UNKNOWN" as the sole network ID.
        }

        if (activeNetworkInfo != null && activeNetworkInfo.getType() == ConnectivityManager.TYPE_WIFI) {

            networkID = "WIFI";

            try {
                WifiManager wifiManager = (WifiManager)context.getSystemService(Context.WIFI_SERVICE);
                WifiInfo wifiInfo = wifiManager.getConnectionInfo();
                if (wifiInfo != null) {
                    String wifiNetworkID = wifiInfo.getBSSID();
                    if (wifiNetworkID.equals("02:00:00:00:00:00")) {
                        // "02:00:00:00:00:00" is reported when the app does not have the ACCESS_COARSE_LOCATION permission:
                        // https://developer.android.com/about/versions/marshmallow/android-6.0-changes#behavior-hardware-id
                        // The Psiphon client should allow the user to opt-in to this permission. If they decline, fail over
                        // to using the WiFi IP address.
                        wifiNetworkID = String.valueOf(wifiInfo.getIpAddress());
                    }
                    networkID += "-" + wifiNetworkID;
                }
            } catch (java.lang.Exception e) {
                // May get exceptions due to missing permissions like android.permission.ACCESS_WIFI_STATE.
                // Fall through and use just "WIFI"
            }

        } else if (activeNetworkInfo != null && activeNetworkInfo.getType() == ConnectivityManager.TYPE_MOBILE) {

            networkID = "MOBILE";

            try {
                TelephonyManager telephonyManager = (TelephonyManager)context.getSystemService(Context.TELEPHONY_SERVICE);
                if (telephonyManager != null) {
                    networkID += "-" + telephonyManager.getNetworkOperator();
                }
            } catch (java.lang.Exception e) {
                // May get exceptions due to missing permissions.
                // Fall through and use just "MOBILE"
            }
        }

        return networkID;
    }

    //----------------------------------------------------------------------------------------------
    // Psiphon Tunnel Core
    //----------------------------------------------------------------------------------------------

    private void startPsiphon(String embeddedServerEntries) throws Exception {
        stopPsiphon();
        mHostService.onDiagnosticMessage("starting Psiphon library");

        // In packet tunnel mode, Psi.start will dup the tun file descriptor
        // passed in via the config. So here we "check out" mTunFd, to ensure
        // it can't be closed before it's duplicated. (This would only happen
        // if stop() is called concurrently with startTunneling(), which should
        // not be done -- this could also cause file descriptor issues in
        // tun2socks mode. With the "check out", a closed and recycled file
        // descriptor will not be copied; but a different race condition takes
        // the place of that one: stop() may fail to close the tun fd. So the
        // prohibition on concurrent calls remains.)
        //
        // In tun2socks mode, the ownership of the fd is transferred to tun2socks.
        // In packet tunnel mode, tunnel code dups the fd and manages  that copy
        // while PsiphonTunnel retains ownership of the original mTunFd copy. Both
        // file descriptors must be closed to halt VpnService, and stop() does
        // this.

        ParcelFileDescriptor tunFd = null;
        int fd = -1;
        if (mUsePacketTunnel) {
            tunFd = mTunFd.getAndSet(null);
            if (tunFd != null) {
                fd = tunFd.getFd();
            }
        }

        try {
            Psi.start(
                    loadPsiphonConfig(mHostService.getContext(), fd),
                    embeddedServerEntries,
                    "",
                    this,
                    isVpnMode(),
                    false        // Do not use IPv6 synthesizer for android
                    );
        } catch (java.lang.Exception e) {
            throw new Exception("failed to start Psiphon library", e);
        } finally {

            if (mUsePacketTunnel) {
                mTunFd.getAndSet(tunFd);
            }

        }

        mHostService.onDiagnosticMessage("Psiphon library started");
    }

    private void stopPsiphon() {
        mHostService.onDiagnosticMessage("stopping Psiphon library");
        Psi.stop();
        mHostService.onDiagnosticMessage("Psiphon library stopped");
    }

    private String loadPsiphonConfig(Context context, int tunFd)
            throws IOException, JSONException {

        // Load settings from the raw resource JSON config file and
        // update as necessary. Then write JSON to disk for the Go client.
        JSONObject json = new JSONObject(mHostService.getPsiphonConfig());

        // On Android, this directory must be set to the app private storage area.
        // The Psiphon library won't be able to use its current working directory
        // and the standard temporary directories do not exist.
        if (!json.has("DataStoreDirectory")) {
            json.put("DataStoreDirectory", context.getFilesDir());
        }

        if (!json.has("RemoteServerListDownloadFilename")) {
            File remoteServerListDownload = new File(context.getFilesDir(), "remote_server_list");
            json.put("RemoteServerListDownloadFilename", remoteServerListDownload.getAbsolutePath());
        }

        File oslDownloadDir = new File(context.getFilesDir(), "osl");
        if (!oslDownloadDir.exists()
                && !oslDownloadDir.mkdirs()) {
            // Failed to create osl directory
            // TODO: proceed anyway?
            throw new IOException("failed to create OSL download directory");
        }
        json.put("ObfuscatedServerListDownloadDirectory", oslDownloadDir.getAbsolutePath());

        // Note: onConnecting/onConnected logic assumes 1 tunnel connection
        json.put("TunnelPoolSize", 1);

        // Continue to run indefinitely until connected
        if (!json.has("EstablishTunnelTimeoutSeconds")) {
            json.put("EstablishTunnelTimeoutSeconds", 0);
        }

        // This parameter is for stats reporting
        if (!json.has("TunnelWholeDevice")) {
            json.put("TunnelWholeDevice", isVpnMode() ? 1 : 0);
        }

        json.put("EmitBytesTransferred", true);

        if (mLocalSocksProxyPort.get() != 0 && (!json.has("LocalSocksProxyPort") || json.getInt("LocalSocksProxyPort") == 0)) {
            // When mLocalSocksProxyPort is set, tun2socks is already configured
            // to use that port value. So we force use of the same port.
            // A side-effect of this is that changing the SOCKS port preference
            // has no effect with restartPsiphon(), a full stop() is necessary.
            json.put("LocalSocksProxyPort", mLocalSocksProxyPort);
        }

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
            try {
                json.put(
                        "TrustedCACertificatesFilename",
                        setupTrustedCertificates(mHostService.getContext()));
            } catch (Exception e) {
                mHostService.onDiagnosticMessage(e.getMessage());
            }
        }

        json.put("DeviceRegion", getDeviceRegion(mHostService.getContext()));

        if (mUsePacketTunnel) {
            json.put("PacketTunnelTunFileDescriptor", tunFd);
            json.put("DisableLocalSocksProxy", true);
            json.put("DisableLocalHTTPProxy", true);
        }

        StringBuilder clientPlatform = new StringBuilder();

        String prefix = mClientPlatformPrefix.get();
        if (prefix.length() > 0) {
            clientPlatform.append(prefix);
        }

        clientPlatform.append("Android_");
        clientPlatform.append(Build.VERSION.RELEASE);
        clientPlatform.append("_");
        clientPlatform.append(mHostService.getContext().getPackageName());

        String suffix = mClientPlatformSuffix.get();
        if (suffix.length() > 0) {
            clientPlatform.append(suffix);
        }

        json.put("ClientPlatform", clientPlatform.toString().replaceAll("[^\\w\\-\\.]", "_"));

        return json.toString();
    }

    private void handlePsiphonNotice(String noticeJSON) {
        try {
            // All notices are sent on as diagnostic messages
            // except those that may contain private user data.
            boolean diagnostic = true;

            JSONObject notice = new JSONObject(noticeJSON);
            String noticeType = notice.getString("noticeType");

            if (noticeType.equals("Tunnels")) {
                int count = notice.getJSONObject("data").getInt("count");
                if (count > 0) {
                    if (isVpnMode()) {
                        routeThroughTunnel();
                    }
                    mHostService.onConnected();
                } else {
                    mHostService.onConnecting();
                }

            } else if (noticeType.equals("AvailableEgressRegions")) {
                JSONArray egressRegions = notice.getJSONObject("data").getJSONArray("regions");
                ArrayList<String> regions = new ArrayList<String>();
                for (int i=0; i<egressRegions.length(); i++) {
                    regions.add(egressRegions.getString(i));
                }
                mHostService.onAvailableEgressRegions(regions);
            } else if (noticeType.equals("SocksProxyPortInUse")) {
                mHostService.onSocksProxyPortInUse(notice.getJSONObject("data").getInt("port"));
            } else if (noticeType.equals("HttpProxyPortInUse")) {
                mHostService.onHttpProxyPortInUse(notice.getJSONObject("data").getInt("port"));
            } else if (noticeType.equals("ListeningSocksProxyPort")) {
                int port = notice.getJSONObject("data").getInt("port");
                setLocalSocksProxyPort(port);
                mHostService.onListeningSocksProxyPort(port);
            } else if (noticeType.equals("ListeningHttpProxyPort")) {
                int port = notice.getJSONObject("data").getInt("port");
                mHostService.onListeningHttpProxyPort(port);
            } else if (noticeType.equals("UpstreamProxyError")) {
                mHostService.onUpstreamProxyError(notice.getJSONObject("data").getString("message"));
            } else if (noticeType.equals("ClientUpgradeDownloaded")) {
                mHostService.onClientUpgradeDownloaded(notice.getJSONObject("data").getString("filename"));
            } else if (noticeType.equals("ClientIsLatestVersion")) {
                mHostService.onClientIsLatestVersion();
            } else if (noticeType.equals("Homepage")) {
                mHostService.onHomepage(notice.getJSONObject("data").getString("url"));
            } else if (noticeType.equals("ClientRegion")) {
                mHostService.onClientRegion(notice.getJSONObject("data").getString("region"));
            } else if (noticeType.equals("SplitTunnelRegion")) {
                mHostService.onSplitTunnelRegion(notice.getJSONObject("data").getString("region"));
            } else if (noticeType.equals("Untunneled")) {
                mHostService.onUntunneledAddress(notice.getJSONObject("data").getString("address"));
            } else if (noticeType.equals("BytesTransferred")) {
                diagnostic = false;
                JSONObject data = notice.getJSONObject("data");
                mHostService.onBytesTransferred(data.getLong("sent"), data.getLong("received"));
            }  else if (noticeType.equals("ActiveAuthorizationIDs")) {
                JSONArray activeAuthorizationIDs = notice.getJSONObject("data").getJSONArray("IDs");
                ArrayList<String> authorizations = new ArrayList<String>();
                for (int i=0; i<activeAuthorizationIDs.length(); i++) {
                    authorizations.add(activeAuthorizationIDs.getString(i));
                }
                mHostService.onActiveAuthorizationIDs(authorizations);
            } else if (noticeType.equals("Exiting")) {
                mHostService.onExiting();
            } else if (noticeType.equals("ActiveTunnel")) {
                if (isVpnMode()) {
                    if (notice.getJSONObject("data").getBoolean("isTCS")) {
                      disableUdpGwKeepalive();
                    } else {
                      enableUdpGwKeepalive();
                    }
                }
            }

            if (diagnostic) {
                String diagnosticMessage = noticeType + ": " + notice.getJSONObject("data").toString();
                mHostService.onDiagnosticMessage(diagnosticMessage);
            }

        } catch (JSONException e) {
            // Ignore notice
        }
    }

    private String setupTrustedCertificates(Context context) throws Exception {

        // Copy the Android system CA store to a local, private cert bundle file.
        //
        // This results in a file that can be passed to SSL_CTX_load_verify_locations
        // for use with OpenSSL modes in tunnel-core.
        // https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_load_verify_locations.html
        //
        // TODO: to use the path mode of load_verify_locations would require emulating
        // the filename scheme used by c_rehash:
        // https://www.openssl.org/docs/manmaster/apps/c_rehash.html
        // http://stackoverflow.com/questions/19237167/the-new-subject-hash-openssl-algorithm-differs

        File directory = context.getDir("PsiphonCAStore", Context.MODE_PRIVATE);

        final String errorMessage = "copy AndroidCAStore failed";
        try {

            File file = new File(directory, "certs.dat");

            // Pave a fresh copy on every run, which ensures we're not using old certs.
            // Note: assumes KeyStore doesn't return revoked certs.
            //
            // TODO: this takes under 1 second, but should we avoid repaving every time?
            file.delete();

            PrintStream output = null;
            try {
                output = new PrintStream(new FileOutputStream(file));

                KeyStore keyStore;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
                    keyStore = KeyStore.getInstance("AndroidCAStore");
                    keyStore.load(null, null);
                } else {
                    keyStore = KeyStore.getInstance("BKS");
                    FileInputStream inputStream = new FileInputStream("/etc/security/cacerts.bks");
                    try {
                        keyStore.load(inputStream, "changeit".toCharArray());
                    } finally {
                        if (inputStream != null) {
                            inputStream.close();
                        }
                    }
                }

                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

                    output.println("-----BEGIN CERTIFICATE-----");
                    String pemCert = new String(Base64.encode(cert.getEncoded(), Base64.NO_WRAP), "UTF-8");
                    // OpenSSL appears to reject the default linebreaking done by Base64.encode,
                    // so we manually linebreak every 64 characters
                    for (int i = 0; i < pemCert.length() ; i+= 64) {
                        output.println(pemCert.substring(i, Math.min(i + 64, pemCert.length())));
                    }
                    output.println("-----END CERTIFICATE-----");
                }

                mHostService.onDiagnosticMessage("prepared PsiphonCAStore");

                return file.getAbsolutePath();

            } finally {
                if (output != null) {
                    output.close();
                }
            }

        } catch (KeyStoreException e) {
            throw new Exception(errorMessage, e);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception(errorMessage, e);
        } catch (CertificateException e) {
            throw new Exception(errorMessage, e);
        } catch (IOException e) {
            throw new Exception(errorMessage, e);
        }
    }

    private static String getDeviceRegion(Context context) {
        String region = "";
        TelephonyManager telephonyManager = (TelephonyManager)context.getSystemService(Context.TELEPHONY_SERVICE);
        if (telephonyManager != null) {
            region = telephonyManager.getSimCountryIso();
            if (region == null) {
                region = "";
            }
            if (region.length() == 0 && telephonyManager.getPhoneType() != TelephonyManager.PHONE_TYPE_CDMA) {
                region = telephonyManager.getNetworkCountryIso();
                if (region == null) {
                    region = "";
                }
            }
        }
        if (region.length() == 0) {
            Locale defaultLocale = Locale.getDefault();
            if (defaultLocale != null) {
                region = defaultLocale.getCountry();
            }
        }
        return region.toUpperCase(Locale.US);
    }

    //----------------------------------------------------------------------------------------------
    // Tun2Socks
    //----------------------------------------------------------------------------------------------

    @TargetApi(Build.VERSION_CODES.HONEYCOMB_MR1)
    private void startTun2Socks(
            final ParcelFileDescriptor vpnInterfaceFileDescriptor,
            final int vpnInterfaceMTU,
            final String vpnIpAddress,
            final String vpnNetMask,
            final String socksServerAddress,
            final String udpgwServerAddress,
            final boolean udpgwTransparentDNS) {
        if (mTun2SocksThread != null) {
            return;
        }
        mTun2SocksThread = new Thread(new Runnable() {
            @Override
            public void run() {
                runTun2Socks(
                        vpnInterfaceFileDescriptor.detachFd(),
                        vpnInterfaceMTU,
                        vpnIpAddress,
                        vpnNetMask,
                        socksServerAddress,
                        udpgwServerAddress,
                        udpgwTransparentDNS ? 1 : 0);
            }
        });
        mTun2SocksThread.start();
        mHostService.onDiagnosticMessage("tun2socks started");
    }

    private void stopTun2Socks() {
        if (mTun2SocksThread != null) {
            try {
                terminateTun2Socks();
                mTun2SocksThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            mTun2SocksThread = null;
            mHostService.onDiagnosticMessage("tun2socks stopped");
        }
    }

    public static void logTun2Socks(String level, String channel, String msg) {
        String logMsg = "tun2socks: " + level + "(" + channel + "): " + msg;
        mPsiphonTunnel.mHostService.onDiagnosticMessage(logMsg);
    }

    private native static int runTun2Socks(
            int vpnInterfaceFileDescriptor,
            int vpnInterfaceMTU,
            String vpnIpAddress,
            String vpnNetMask,
            String socksServerAddress,
            String udpgwServerAddress,
            int udpgwTransparentDNS);

    private native static int terminateTun2Socks();

    private native static int enableUdpGwKeepalive();
    private native static int disableUdpGwKeepalive();

    //----------------------------------------------------------------------------------------------
    // Implementation: Network Utils
    //----------------------------------------------------------------------------------------------

    private static boolean hasNetworkConnectivity(Context context) {
        ConnectivityManager connectivityManager =
                (ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivityManager == null) {
            return false;
        }
        NetworkInfo networkInfo = connectivityManager.getActiveNetworkInfo();
        return networkInfo != null && networkInfo.isConnected();
    }

    private static class PrivateAddress {
        final public String mIpAddress;
        final public String mSubnet;
        final public int mPrefixLength;
        final public String mRouter;
        public PrivateAddress(String ipAddress, String subnet, int prefixLength, String router) {
            mIpAddress = ipAddress;
            mSubnet = subnet;
            mPrefixLength = prefixLength;
            mRouter = router;
        }
    }

    private static PrivateAddress selectPrivateAddress() throws Exception {
        // Select one of 10.0.0.1, 172.16.0.1, or 192.168.0.1 depending on
        // which private address range isn't in use.

        Map<String, PrivateAddress> candidates = new HashMap<String, PrivateAddress>();
        candidates.put( "10", new PrivateAddress("10.0.0.1",    "10.0.0.0",     8, "10.0.0.2"));
        candidates.put("172", new PrivateAddress("172.16.0.1",  "172.16.0.0",  12, "172.16.0.2"));
        candidates.put("192", new PrivateAddress("192.168.0.1", "192.168.0.0", 16, "192.168.0.2"));
        candidates.put("169", new PrivateAddress("169.254.1.1", "169.254.1.0", 24, "169.254.1.2"));

        List<NetworkInterface> netInterfaces;
        try {
            netInterfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
        } catch (SocketException e) {
            throw new Exception("selectPrivateAddress failed", e);
        }

        for (NetworkInterface netInterface : netInterfaces) {
            for (InetAddress inetAddress : Collections.list(netInterface.getInetAddresses())) {
                String ipAddress = inetAddress.getHostAddress();
                if (InetAddressUtils.isIPv4Address(ipAddress)) {
                    if (ipAddress.startsWith("10.")) {
                        candidates.remove("10");
                    }
                    else if (
                            ipAddress.length() >= 6 &&
                                    ipAddress.substring(0, 6).compareTo("172.16") >= 0 &&
                                    ipAddress.substring(0, 6).compareTo("172.31") <= 0) {
                        candidates.remove("172");
                    }
                    else if (ipAddress.startsWith("192.168")) {
                        candidates.remove("192");
                    }
                }
            }
        }

        if (candidates.size() > 0) {
            return candidates.values().iterator().next();
        }

        throw new Exception("no private address available");
    }

    public static String getFirstActiveNetworkDnsResolver(Context context)
            throws Exception {
        Collection<InetAddress> dnsResolvers = getActiveNetworkDnsResolvers(context);
        if (!dnsResolvers.isEmpty()) {
            // strip the leading slash e.g., "/192.168.1.1"
            String dnsResolver = dnsResolvers.iterator().next().toString();
            if (dnsResolver.startsWith("/")) {
                dnsResolver = dnsResolver.substring(1);
            }
            return dnsResolver;
        }
        throw new Exception("no active network DNS resolver");
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private static Collection<InetAddress> getActiveNetworkDnsResolvers(Context context)
            throws Exception {
        final String errorMessage = "getActiveNetworkDnsResolvers failed";
        ArrayList<InetAddress> dnsAddresses = new ArrayList<InetAddress>();
        try {
            // Hidden API
            // - only available in Android 4.0+
            // - no guarantee will be available beyond 4.2, or on all vendor devices
            ConnectivityManager connectivityManager =
                    (ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
            Class<?> LinkPropertiesClass = Class.forName("android.net.LinkProperties");
            Method getActiveLinkPropertiesMethod = ConnectivityManager.class.getMethod("getActiveLinkProperties", new Class []{});
            Object linkProperties = getActiveLinkPropertiesMethod.invoke(connectivityManager);
            if (linkProperties != null) {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
                    Method getDnsesMethod = LinkPropertiesClass.getMethod("getDnses", new Class []{});
                    Collection<?> dnses = (Collection<?>)getDnsesMethod.invoke(linkProperties);
                    for (Object dns : dnses) {
                        dnsAddresses.add((InetAddress)dns);
                    }
                } else {
                    // LinkProperties is public in API 21 (and the DNS function signature has changed)
                    for (InetAddress dns : ((LinkProperties)linkProperties).getDnsServers()) {
                        dnsAddresses.add(dns);
                    }
                }
            }
        } catch (ClassNotFoundException e) {
            throw new Exception(errorMessage, e);
        } catch (NoSuchMethodException e) {
            throw new Exception(errorMessage, e);
        } catch (IllegalArgumentException e) {
            throw new Exception(errorMessage, e);
        } catch (IllegalAccessException e) {
            throw new Exception(errorMessage, e);
        } catch (InvocationTargetException e) {
            throw new Exception(errorMessage, e);
        } catch (NullPointerException e) {
            throw new Exception(errorMessage, e);
        }

        return dnsAddresses;
    }

    //----------------------------------------------------------------------------------------------
    // Exception
    //----------------------------------------------------------------------------------------------

    public static class Exception extends java.lang.Exception {
        private static final long serialVersionUID = 1L;
        public Exception(String message) {
            super(message);
        }
        public Exception(String message, Throwable cause) {
            super(message + ": " + cause.getMessage());
        }
    }
}
