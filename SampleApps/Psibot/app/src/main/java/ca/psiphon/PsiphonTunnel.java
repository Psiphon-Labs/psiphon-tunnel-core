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

package ca.psiphon;

import android.annotation.TargetApi;
import android.content.Context;
import android.net.ConnectivityManager;
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

import go.psi.Psi;

public class PsiphonTunnel extends Psi.PsiphonProvider.Stub {

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
        public void onSplitTunnelRegion(String region);
        public void onUntunneledAddress(String address);
        public void onBytesTransferred(long sent, long received);
        public void onStartedWaitingForNetworkConnectivity();
    }

    private final HostService mHostService;
    private PrivateAddress mPrivateAddress;
    private AtomicReference<ParcelFileDescriptor> mTunFd;
    private AtomicInteger mLocalSocksProxyPort;
    private AtomicBoolean mRoutingThroughTunnel;
    private Thread mTun2SocksThread;
    private AtomicBoolean mIsWaitingForNetworkConnectivity;

    // Only one PsiphonVpn instance may exist at a time, as the underlying
    // go.psi.Psi and tun2socks implementations each contain global state.
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
        mTunFd = new AtomicReference<ParcelFileDescriptor>();
        mLocalSocksProxyPort = new AtomicInteger(0);
        mRoutingThroughTunnel = new AtomicBoolean(false);
        mIsWaitingForNetworkConnectivity = new AtomicBoolean(false);
    }

    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    //----------------------------------------------------------------------------------------------
    // Public API
    //----------------------------------------------------------------------------------------------

    // To start, call in sequence: startRouting(), then startTunneling(). After startRouting()
    // succeeds, the caller must call stop() to clean up.

    // Returns true when the VPN routing is established; returns false if the VPN could not
    // be started due to lack of prepare or revoked permissions (called should re-prepare and
    // try again); throws exception for other error conditions.
    public synchronized boolean startRouting() throws Exception {
        return startVpn();
    }

    // Throws an exception in error conditions. In the case of an exception, the routing
    // started by startRouting() is not immediately torn down (this allows the caller to control
    // exactly when VPN routing is stopped); caller should call stop() to clean up.
    public synchronized void startTunneling(String embeddedServerEntries) throws Exception {
        startPsiphon(embeddedServerEntries);
    }

    public synchronized void restartPsiphon() throws Exception {
        stopPsiphon();
        startPsiphon("");
    }

    public synchronized void stop() {
        stopVpn();
        stopPsiphon();
        mLocalSocksProxyPort.set(0);
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

        mPrivateAddress = selectPrivateAddress();

        Locale previousLocale = Locale.getDefault();

        final String errorMessage = "startVpn failed";
        try {
            // Workaround for https://code.google.com/p/android/issues/detail?id=61096
            Locale.setDefault(new Locale("en"));

            ParcelFileDescriptor tunFd =
                    ((VpnService.Builder) mHostService.newVpnServiceBuilder())
                            .setSession(mHostService.getAppName())
                            .setMtu(VPN_INTERFACE_MTU)
                            .addAddress(mPrivateAddress.mIpAddress, mPrivateAddress.mPrefixLength)
                            .addRoute("0.0.0.0", 0)
                            .addRoute(mPrivateAddress.mSubnet, mPrivateAddress.mPrefixLength)
                            .addDnsServer(mPrivateAddress.mRouter)
                            .establish();
            if (tunFd == null) {
                // As per http://developer.android.com/reference/android/net/VpnService.Builder.html#establish%28%29,
                // this application is no longer prepared or was revoked.
                return false;
            }
            mTunFd.set(tunFd);

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
        return mTunFd.get() != null;
    }

    private void setLocalSocksProxyPort(int port) {
        mLocalSocksProxyPort.set(port);
    }

    private void routeThroughTunnel() {
        if (!mRoutingThroughTunnel.compareAndSet(false, true)) {
            return;
        }
        String socksServerAddress = "127.0.0.1:" + Integer.toString(mLocalSocksProxyPort.get());
        String udpgwServerAddress = "127.0.0.1:" + Integer.toString(UDPGW_SERVER_PORT);
        startTun2Socks(
                mTunFd.get(),
                VPN_INTERFACE_MTU,
                mPrivateAddress.mRouter,
                VPN_INTERFACE_NETMASK,
                socksServerAddress,
                udpgwServerAddress,
                true);
        mHostService.onDiagnosticMessage("routing through tunnel");

        // TODO: should double-check tunnel routing; see:
        // https://bitbucket.org/psiphon/psiphon-circumvention-system/src/1dc5e4257dca99790109f3bf374e8ab3a0ead4d7/Android/PsiphonAndroidLibrary/src/com/psiphon3/psiphonlibrary/TunnelCore.java?at=default#cl-779
    }

    private void stopVpn() {
        ParcelFileDescriptor tunFd = mTunFd.getAndSet(null);
        if (tunFd != null) {
            try {
                tunFd.close();
            } catch (IOException e) {
            }
        }
        waitStopTun2Socks();
        mRoutingThroughTunnel.set(false);
    }

    //----------------------------------------------------------------------------------------------
    // PsiphonProvider (Core support) interface implementation
    //----------------------------------------------------------------------------------------------

    @Override
    public void Notice(String noticeJSON) {
        handlePsiphonNotice(noticeJSON);
    }

    @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    @Override
    public void BindToDevice(long fileDescriptor) throws Exception {
        if (!((VpnService)mHostService.getVpnService()).protect((int)fileDescriptor)) {
            throw new Exception("protect socket failed");
        }
    }

    @Override
    public long HasNetworkConnectivity() {
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
    public String GetPrimaryDnsServer() {
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
    public String GetSecondaryDnsServer() {
        return DEFAULT_SECONDARY_DNS_SERVER;
    }

    //----------------------------------------------------------------------------------------------
    // Psiphon Tunnel Core
    //----------------------------------------------------------------------------------------------

    private void startPsiphon(String embeddedServerEntries) throws Exception {
        stopPsiphon();
        mHostService.onDiagnosticMessage("starting Psiphon library");
        try {
            Psi.Start(
                    loadPsiphonConfig(mHostService.getContext()),
                    embeddedServerEntries,
                    this,
                    isVpnMode());
        } catch (java.lang.Exception e) {
            throw new Exception("failed to start Psiphon library", e);
        }
        mHostService.onDiagnosticMessage("Psiphon library started");
    }

    private void stopPsiphon() {
        mHostService.onDiagnosticMessage("stopping Psiphon library");
        Psi.Stop();
        mHostService.onDiagnosticMessage("Psiphon library stopped");
    }

    private String loadPsiphonConfig(Context context)
            throws IOException, JSONException {

        // Load settings from the raw resource JSON config file and
        // update as necessary. Then write JSON to disk for the Go client.
        JSONObject json = new JSONObject(mHostService.getPsiphonConfig());

        // On Android, these directories must be set to the app private storage area.
        // The Psiphon library won't be able to use its current working directory
        // and the standard temporary directories do not exist.
        json.put("DataStoreDirectory", context.getFilesDir());
        json.put("DataStoreTempDirectory", context.getCacheDir());

        // Note: onConnecting/onConnected logic assumes 1 tunnel connection
        json.put("TunnelPoolSize", 1);

        // Continue to run indefinitely until connected
        json.put("EstablishTunnelTimeoutSeconds", 0);

        // This parameter is for stats reporting
        json.put("TunnelWholeDevice", isVpnMode() ? 1 : 0);

        json.put("EmitBytesTransferred", true);

        if (mLocalSocksProxyPort.get() != 0) {
            // When mLocalSocksProxyPort is set, tun2socks is already configured
            // to use that port value. So we force use of the same port.
            // A side-effect of this is that changing the SOCKS port preference
            // has no effect with restartPsiphon(), a full stop() is necessary.
            json.put("LocalSocksProxyPort", mLocalSocksProxyPort);
        }

        json.put("UseIndistinguishableTLS", true);

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
            json.put("UseTrustedCACertificatesForStockTLS", true);
        }

        try {
            // Also enable indistinguishable TLS for HTTPS requests that
            // require system CAs.
            json.put(
                    "TrustedCACertificatesFilename",
                    setupTrustedCertificates(mHostService.getContext()));
        } catch (Exception e) {
            mHostService.onDiagnosticMessage(e.getMessage());
        }

        json.put("DeviceRegion", getDeviceRegion(mHostService.getContext()));

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

            } else if (noticeType.equals("Homepage")) {
                mHostService.onHomepage(notice.getJSONObject("data").getString("url"));

            } else if (noticeType.equals("ClientRegion")) {
                mHostService.onClientRegion(notice.getJSONObject("data").getString("region"));

            } else if (noticeType.equals("SplitTunnelRegion")) {
                mHostService.onSplitTunnelRegion(notice.getJSONObject("data").getString("region"));

            } else if (noticeType.equals("UntunneledAddress")) {
                mHostService.onUntunneledAddress(notice.getJSONObject("data").getString("address"));

            } else if (noticeType.equals("BytesTransferred")) {
                diagnostic = false;
                JSONObject data = notice.getJSONObject("data");
                mHostService.onBytesTransferred(data.getLong("sent"), data.getLong("received"));
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
            if (region.length() == 0 && telephonyManager.getPhoneType() != TelephonyManager.PHONE_TYPE_CDMA) {
                region = telephonyManager.getNetworkCountryIso();
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
        mTun2SocksThread = new Thread(new Runnable() {
            @Override
            public void run() {
                runTun2Socks(
                        vpnInterfaceFileDescriptor.getFd(),
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

    private void waitStopTun2Socks() {
        if (mTun2SocksThread != null) {
            try {
                // Assumes mTunFd has been closed, which signals tun2socks to exit
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

    static {
        System.loadLibrary("tun2socks");
    }

    //----------------------------------------------------------------------------------------------
    // Implementation: Network Utils
    //----------------------------------------------------------------------------------------------

    private static boolean hasNetworkConnectivity(Context context) {
        ConnectivityManager connectivityManager =
                (ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
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
