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
import android.net.LinkProperties;
import android.net.NetworkInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import org.apache.http.conn.util.InetAddressUtils;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import go.Go;
import go.psi.Psi;

public class PsiphonVpn extends Psi.PsiphonProvider.Stub {

    public interface HostService {
        public String getAppName();
        public VpnService getVpnService();
        public VpnService.Builder newVpnServiceBuilder();
        public InputStream getPsiphonConfigResource();
        public void customizeConfigParameters(JSONObject config);
        public void logWarning(String message);
        public void logInfo(String message);
    }

    private final HostService mHostService;
    private PrivateAddress mPrivateAddress;
    private ParcelFileDescriptor mTunFd;
    private int mLocalSocksProxyPort;
    private boolean mRoutingThroughTunnel;
    private Thread mTun2SocksThread;

    // Only one PsiphonVpn instance may exist at a time, as the underlying
    // go.psi.Psi and tun2socks implementations each contain global state.
    private static PsiphonVpn mPsiphonVpn;

    public static synchronized PsiphonVpn newPsiphonVpn(HostService hostService) {
        if (mPsiphonVpn != null) {
            mPsiphonVpn.stop();
        }
        mPsiphonVpn = new PsiphonVpn(hostService);
        return mPsiphonVpn;
    }

    private PsiphonVpn(HostService hostService) {
        Go.init(hostService.getVpnService());
        mHostService = hostService;
        mLocalSocksProxyPort = 0;
        mRoutingThroughTunnel = false;
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
    public synchronized void startTunneling() throws Exception {
        if (mTunFd == null) {
            // Most likely, startRouting() was not called before this function.
            throw new Exception("startTunneling: missing tun fd");
        }
        startPsiphon();
    }

    public synchronized void restartPsiphon() throws Exception {
        stopPsiphon();
        startPsiphon();
    }

    public synchronized void stop() {
        stopPsiphon();
        stopVpn();
        mLocalSocksProxyPort = 0;
    }

    //----------------------------------------------------------------------------------------------
    // VPN Routing
    //----------------------------------------------------------------------------------------------

    private final static String VPN_INTERFACE_NETMASK = "255.255.255.0";
    private final static int VPN_INTERFACE_MTU = 1500;
    private final static int UDPGW_SERVER_PORT = 7300;

    private boolean startVpn() throws Exception {

        mPrivateAddress = selectPrivateAddress();

        Locale previousLocale = Locale.getDefault();

        final String errorMessage = "startVpn failed";
        try {
            // Workaround for https://code.google.com/p/android/issues/detail?id=61096
            Locale.setDefault(new Locale("en"));

            mTunFd = mHostService.newVpnServiceBuilder()
                    .setSession(mHostService.getAppName())
                    .setMtu(VPN_INTERFACE_MTU)
                    .addAddress(mPrivateAddress.mIpAddress, mPrivateAddress.mPrefixLength)
                    .addRoute("0.0.0.0", 0)
                    .addRoute(mPrivateAddress.mSubnet, mPrivateAddress.mPrefixLength)
                    .addDnsServer(mPrivateAddress.mRouter)
                    .establish();
            if (mTunFd == null) {
                // As per http://developer.android.com/reference/android/net/VpnService.Builder.html#establish%28%29,
                // this application is no longer prepared or was revoked.
                return false;
            }
            mHostService.logInfo("VPN established");

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

    private synchronized void setLocalSocksProxyPort(int port) {
        mLocalSocksProxyPort = port;
    }

    private synchronized void routeThroughTunnel() {
        if (mRoutingThroughTunnel) {
            return;
        }
        mRoutingThroughTunnel = true;
        String socksServerAddress = "127.0.0.1:" + Integer.toString(mLocalSocksProxyPort);
        String udpgwServerAddress = "127.0.0.1:" + Integer.toString(UDPGW_SERVER_PORT);
        startTun2Socks(
                mTunFd,
                VPN_INTERFACE_MTU,
                mPrivateAddress.mRouter,
                VPN_INTERFACE_NETMASK,
                socksServerAddress,
                udpgwServerAddress,
                true);
        mTunFd = null;
        mHostService.logInfo("routing through tunnel");

        // TODO: should double-check tunnel routing; see:
        // https://bitbucket.org/psiphon/psiphon-circumvention-system/src/1dc5e4257dca99790109f3bf374e8ab3a0ead4d7/Android/PsiphonAndroidLibrary/src/com/psiphon3/psiphonlibrary/TunnelCore.java?at=default#cl-779
    }

    private void stopVpn() {
        if (mTunFd != null) {
            try {
                mTunFd.close();
            } catch (IOException e) {
            }
            mTunFd = null;
        }
        stopTun2Socks();
        mRoutingThroughTunnel = false;
    }

    //----------------------------------------------------------------------------------------------
    // PsiphonProvider (Core support) interface implementation
    //----------------------------------------------------------------------------------------------

    @Override
    public void Notice(String noticeJSON) {
        handlePsiphonNotice(noticeJSON);
    }

    @Override
    public void BindToDevice(long fileDescriptor) throws Exception {
        if (!mHostService.getVpnService().protect((int)fileDescriptor)) {
            throw new Exception("protect socket failed");
        }
    }

    @Override
    public long HasNetworkConnectivity() {
        // TODO: change to bool return value once gobind supports that type
        return hasNetworkConnectivity(mHostService.getVpnService()) ? 1 : 0;
    }

    //----------------------------------------------------------------------------------------------
    // Psiphon Tunnel Core
    //----------------------------------------------------------------------------------------------

    private void startPsiphon() throws Exception {
        stopPsiphon();
        mHostService.logInfo("starting Psiphon");
        try {
            Psi.Start(
                loadPsiphonConfig(mHostService.getVpnService()),
                "", // TODO: supply embedded server list
                this);
        } catch (java.lang.Exception e) {
            throw new Exception("failed to start Psiphon", e);
        }
        mHostService.logInfo("Psiphon started");
    }

    private void stopPsiphon() {
        mHostService.logInfo("stopping Psiphon");
        Psi.Stop();
        mHostService.logInfo("Psiphon stopped");
    }

    private String loadPsiphonConfig(Context context)
            throws IOException, JSONException {

        // If we can obtain a DNS resolver for the active network,
        // prefer that for DNS resolution in BindToDevice mode.
        String dnsResolver = null;
        try {
            dnsResolver = getFirstActiveNetworkDnsResolver(context);
        } catch (Exception e) {
            mHostService.logWarning("failed to get active network DNS resolver: " + e.getMessage());
            // Proceed with default value in config file
        }

        // Load settings from the raw resource JSON config file and
        // update as necessary. Then write JSON to disk for the Go client.
        JSONObject json = new JSONObject(
                readInputStreamToString(
                    mHostService.getPsiphonConfigResource()));

        if (dnsResolver != null) {
            json.put("BindToDeviceDnsServer", dnsResolver);
        }

        // On Android, these directories must be set to the app private storage area.
        // The Psiphon library won't be able to use its current working directory
        // and the standard temporary directories do not exist.
        json.put("DataStoreDirectory", context.getFilesDir());
        json.put("DataStoreTempDirectory", context.getCacheDir());

        mPsiphonVpn.mHostService.customizeConfigParameters(json);

        if (mLocalSocksProxyPort != 0) {
            // When mLocalSocksProxyPort is set, tun2socks is already configured
            // to use that port value. So we force use of the same port.
            // A side-effect of this is that changing the SOCKS port preference
            // has no effect with restartPsiphon(), a full stop() is necessary.
            json.put("LocalSocksProxyPort", mLocalSocksProxyPort);
        }

        return json.toString();
    }

    private void handlePsiphonNotice(String noticeJSON) {
        try {
            JSONObject notice = new JSONObject(noticeJSON);
            String noticeType = notice.getString("noticeType");
            if (noticeType.equals("Tunnels")) {
                int count = notice.getJSONObject("data").getInt("count");
                if (count > 0) {
                    routeThroughTunnel();
                }
            } else if (noticeType.equals("ListeningSocksProxyPort")) {
                setLocalSocksProxyPort(notice.getJSONObject("data").getInt("port"));
            /*
            } else if (noticeType.equals("Homepage")) {
                String homePage = notice.getJSONObject("data").getString("url");
            */
            }
            String displayNotice = noticeType + " " + notice.getJSONObject("data").toString();
            mHostService.logInfo(displayNotice);
        } catch (JSONException e) {
            // Ignore notice
        }
    }

    //----------------------------------------------------------------------------------------------
    // Tun2Socks
    //----------------------------------------------------------------------------------------------

    private void startTun2Socks(
            final ParcelFileDescriptor vpnInterfaceFileDescriptor,
            final int vpnInterfaceMTU,
            final String vpnIpAddress,
            final String vpnNetMask,
            final String socksServerAddress,
            final String udpgwServerAddress,
            final boolean udpgwTransparentDNS) {
        stopTun2Socks();
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
        mPsiphonVpn = this;
        mTun2SocksThread.start();
        mHostService.logInfo("tun2socks started");
    }

    private void stopTun2Socks() {
        if (mTun2SocksThread != null) {
            terminateTun2Socks();
            try {
                mTun2SocksThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            mTun2SocksThread = null;
            mHostService.logInfo("tun2socks stopped");
        }
    }

    public static void logTun2Socks(String level, String channel, String msg) {
        String logMsg = "tun2socks: " + level + "(" + channel + "): " + msg;
        mPsiphonVpn.mHostService.logWarning(logMsg);
    }

    private native static int runTun2Socks(
            int vpnInterfaceFileDescriptor,
            int vpnInterfaceMTU,
            String vpnIpAddress,
            String vpnNetMask,
            String socksServerAddress,
            String udpgwServerAddress,
            int udpgwTransparentDNS);

    private native static void terminateTun2Socks();

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
        candidates.put("10", new PrivateAddress("10.0.0.1",    "10.0.0.0",     8, "10.0.0.2"));
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
    // Implementation: Resource Utils
    //----------------------------------------------------------------------------------------------

    private static String readInputStreamToString(InputStream inputStream) throws IOException {
        return new String(readInputStreamToBytes(inputStream), "UTF-8");
    }

    private static byte[] readInputStreamToBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int readCount;
        byte[] buffer = new byte[16384];
        while ((readCount = inputStream.read(buffer, 0, buffer.length)) != -1) {
            outputStream.write(buffer, 0, readCount);
        }
        outputStream.flush();
        inputStream.close();
        return outputStream.toByteArray();
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
