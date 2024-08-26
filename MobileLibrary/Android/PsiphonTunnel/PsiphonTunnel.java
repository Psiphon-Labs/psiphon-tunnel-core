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
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.Base64;

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
import java.net.Inet4Address;
import java.net.Inet6Address;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import psi.Psi;
import psi.PsiphonProvider;
import psi.PsiphonProviderNetwork;
import psi.PsiphonProviderNoticeHandler;
import psi.PsiphonProviderFeedbackHandler;

public class PsiphonTunnel {

    public interface HostLogger {
        default public void onDiagnosticMessage(String message) {}
    }

    // Protocol used to communicate the outcome of feedback upload operations to the application
    // using PsiphonTunnelFeedback.
    public interface HostFeedbackHandler {
        // Callback which is invoked once the feedback upload has completed.
        // If the exception is non-null, then the upload failed.
        default public void sendFeedbackCompleted(java.lang.Exception e) {}
    }

    public interface HostLibraryLoader {
        default public void loadLibrary(String library) {
            System.loadLibrary(library);
        }
    }

    public interface HostService extends HostLogger, HostLibraryLoader {

        public String getAppName();
        public Context getContext();
        public String getPsiphonConfig();

        default public Object getVpnService() {return null;} // Object must be a VpnService (Android < 4 cannot reference this class name)
        default public Object newVpnServiceBuilder() {return null;} // Object must be a VpnService.Builder (Android < 4 cannot reference this class name)
        default public void onAvailableEgressRegions(List<String> regions) {}
        default public void onSocksProxyPortInUse(int port) {}
        default public void onHttpProxyPortInUse(int port) {}
        default public void onListeningSocksProxyPort(int port) {}
        default public void onListeningHttpProxyPort(int port) {}
        default public void onUpstreamProxyError(String message) {}
        default public void onConnecting() {}
        default public void onConnected() {}
        default public void onHomepage(String url) {}
        default public void onClientRegion(String region) {}
        default public void onClientAddress(String address) {}
        default public void onClientUpgradeDownloaded(String filename) {}
        default public void onClientIsLatestVersion() {}
        default public void onSplitTunnelRegions(List<String> regions) {}
        default public void onUntunneledAddress(String address) {}
        default public void onBytesTransferred(long sent, long received) {}
        default public void onStartedWaitingForNetworkConnectivity() {}
        default public void onStoppedWaitingForNetworkConnectivity() {}
        default public void onActiveAuthorizationIDs(List<String> authorizations) {}
        default public void onTrafficRateLimits(long upstreamBytesPerSecond, long downstreamBytesPerSecond) {}
        default public void onApplicationParameters(Object parameters) {}
        default public void onServerAlert(String reason, String subject, List<String> actionURLs) {}
        /**
         * Called when tunnel-core reports that a selected in-proxy mode --
         * including running a proxy; or running a client in personal pairing
         * mode -- cannot function without an app upgrade. The receiver
         * should alert the user to upgrade the app and/or disable the
         * unsupported mode(s). This callback is followed by a tunnel-core
         * shutdown.
         */
        default void onInproxyMustUpgrade() {}
        /**
         * Called when tunnel-core reports proxy usage statistics.
         * By default onInproxyProxyActivity is disabled. Enable it by setting
         * EmitInproxyProxyActivity to true in the Psiphon config.
         * @param connectingClients Number of clients connecting to the proxy.
         * @param connectedClients Number of clients currently connected to the proxy.
         * @param bytesUp  Bytes uploaded through the proxy since the last report.
         * @param bytesDown Bytes downloaded through the proxy since the last report.
         */
        default void onInproxyProxyActivity(int connectingClients, int connectedClients,long bytesUp, long bytesDown) {}
        /**
         * Called when tunnel-core reports connected server region information.
         * @param region The server region received.
         */
        default public void onConnectedServerRegion(String region) {}
        default public void onExiting() {}
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
    private final boolean mShouldRouteThroughTunnelAutomatically;
    private final NetworkMonitor mNetworkMonitor;
    private AtomicReference<String> mActiveNetworkType;
    private AtomicReference<String> mActiveNetworkDNSServers;

    // Only one PsiphonVpn instance may exist at a time, as the underlying
    // psi.Psi and tun2socks implementations each contain global state.
    private static PsiphonTunnel mPsiphonTunnel;

    public static synchronized PsiphonTunnel newPsiphonTunnel(HostService hostService) {
        return newPsiphonTunnelImpl(hostService, true);
    }

    // The two argument override in case the host app wants to take control over calling routeThroughTunnel()
    public static synchronized PsiphonTunnel newPsiphonTunnel(HostService hostService, boolean shouldRouteThroughTunnelAutomatically) {
        return newPsiphonTunnelImpl(hostService, shouldRouteThroughTunnelAutomatically);
    }

    private static PsiphonTunnel newPsiphonTunnelImpl(HostService hostService, boolean shouldRouteThroughTunnelAutomatically) {
        if (mPsiphonTunnel != null) {
            mPsiphonTunnel.stop();
        }
        // Load the native go code embedded in psi.aar
        hostService.loadLibrary("gojni");
        mPsiphonTunnel = new PsiphonTunnel(hostService, shouldRouteThroughTunnelAutomatically);
        return mPsiphonTunnel;
    }

    // Returns default path where upgrade downloads will be paved. Only applicable if
    // DataRootDirectory was not set in the outer config. If DataRootDirectory was set in the
    // outer config, use getUpgradeDownloadFilePath with its value instead.
    public static String getDefaultUpgradeDownloadFilePath(Context context) {
        return Psi.upgradeDownloadFilePath(defaultDataRootDirectory(context).getAbsolutePath());
    }

    // Returns the path where upgrade downloads will be paved relative to the configured
    // DataRootDirectory.
    public static String getUpgradeDownloadFilePath(String dataRootDirectoryPath) {
        return Psi.upgradeDownloadFilePath(dataRootDirectoryPath);
    }

    private static File defaultDataRootDirectory(Context context) {
        return context.getFileStreamPath("ca.psiphon.PsiphonTunnel.tunnel-core");
    }

    private PsiphonTunnel(HostService hostService, boolean shouldRouteThroughTunnelAutomatically) {
        mHostService = hostService;
        mVpnMode = new AtomicBoolean(false);
        mTunFd = new AtomicReference<ParcelFileDescriptor>();
        mLocalSocksProxyPort = new AtomicInteger(0);
        mRoutingThroughTunnel = new AtomicBoolean(false);
        mIsWaitingForNetworkConnectivity = new AtomicBoolean(false);
        mClientPlatformPrefix = new AtomicReference<String>("");
        mClientPlatformSuffix = new AtomicReference<String>("");
        mShouldRouteThroughTunnelAutomatically = shouldRouteThroughTunnelAutomatically;
        mActiveNetworkType = new AtomicReference<String>("");
        mActiveNetworkDNSServers = new AtomicReference<String>("");
        mNetworkMonitor = new NetworkMonitor(new NetworkMonitor.NetworkChangeListener() {
            @Override
            public void onChanged() {
                try {
                    reconnectPsiphon();
                } catch (Exception e) {
                    mHostService.onDiagnosticMessage("reconnect error: " + e);
                }
            }
        });
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
    // In case the host application requests manual control of routing through tunnel by calling
    // PsiphonTunnel.newPsiphonTunnel(HostService hostservice, shouldRouteThroughTunnelAutomatically = false)
    // it should also call routeThroughTunnel() at some point, usually after receiving onConnected() callback,
    // otherwise it will be called automatically.

    // Returns true when the VPN routing is established; returns false if the VPN could not
    // be started due to lack of prepare or revoked permissions (called should re-prepare and
    // try again); throws exception for other error conditions.
    public synchronized boolean startRouting() throws Exception {
        // Load tun2socks library embedded in the aar
        // If this method is called more than once with the same library name, the second and subsequent calls are ignored.
        // http://docs.oracle.com/javase/7/docs/api/java/lang/Runtime.html#loadLibrary%28java.lang.String%29
        mHostService.loadLibrary("tun2socks");
        return startVpn();
    }

    // Starts routing traffic via tunnel by starting tun2socks if it is not running already.
    // This will be called automatically right after tunnel gets connected in case the host application
    // did not request a manual control over this functionality, see PsiphonTunnel.newPsiphonTunnel
    public void routeThroughTunnel() {
        if (!mRoutingThroughTunnel.compareAndSet(false, true)) {
            return;
        }
        ParcelFileDescriptor tunFd = mTunFd.get();
        if (tunFd == null) {
            return;
        }

        String socksServerAddress = "127.0.0.1:" + Integer.toString(mLocalSocksProxyPort.get());
        String udpgwServerAddress = "127.0.0.1:" + Integer.toString(UDPGW_SERVER_PORT);

        // We may call routeThroughTunnel and stopRouteThroughTunnel more than once within the same
        // VPN session. Since stopTun2Socks() closes the FD passed to startTun2Socks() we will use a
        // dup of the original tun FD and close the original only when we call stopVpn().
        //
        // Note that ParcelFileDescriptor.dup() may throw an IOException.
        try {
            startTun2Socks(
                    tunFd.dup(),
                    VPN_INTERFACE_MTU,
                    mPrivateAddress.mRouter,
                    VPN_INTERFACE_NETMASK,
                    socksServerAddress,
                    udpgwServerAddress,
                    true);
            mHostService.onDiagnosticMessage("routing through tunnel");

            // TODO: should double-check tunnel routing; see:
            // https://bitbucket.org/psiphon/psiphon-circumvention-system/src/1dc5e4257dca99790109f3bf374e8ab3a0ead4d7/Android/PsiphonAndroidLibrary/src/com/psiphon3/psiphonlibrary/TunnelCore.java?at=default#cl-779
        } catch (IOException e) {
            mHostService.onDiagnosticMessage("routing through tunnel error: " + e);
        }
    }

    public void stopRouteThroughTunnel() {
        if (mRoutingThroughTunnel.compareAndSet(true, false)) {
            stopTun2Socks();
        }
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

    public synchronized void reconnectPsiphon() throws Exception {
        Psi.reconnectTunnel();
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

    // The interface for managing the Psiphon feedback upload operations.
    // Warnings:
    // - Should not be used in the same process as PsiphonTunnel.
    // - Only a single instance of PsiphonTunnelFeedback should be used at a time. Using multiple
    // instances in parallel, or concurrently, will result in undefined behavior.
    public static class PsiphonTunnelFeedback {
        private final ExecutorService workQueue = Executors.newSingleThreadExecutor();
        private final ExecutorService callbackQueue = Executors.newSingleThreadExecutor();

        void shutdownAndAwaitTermination(ExecutorService pool) {
            try {
                // Wait a while for existing tasks to terminate
                if (!pool.awaitTermination(5, TimeUnit.SECONDS)) {
                    pool.shutdownNow(); // Cancel currently executing tasks
                    // Wait a while for tasks to respond to being cancelled
                    if (!pool.awaitTermination(5, TimeUnit.SECONDS)) {
                        System.err.println("PsiphonTunnelFeedback: pool did not terminate");
                        return;
                    }
                }
            } catch (InterruptedException ie) {
                // (Re-)Cancel if current thread also interrupted
                pool.shutdownNow();
                // Preserve interrupt status
                Thread.currentThread().interrupt();
            }
        }

        // Upload a feedback package to Psiphon Inc. The app collects feedback and diagnostics
        // information in a particular format, then calls this function to upload it for later
        // investigation. The feedback compatible config and upload path must be provided by
        // Psiphon Inc. This call is asynchronous and returns before the upload completes. The
        // operation has completed when sendFeedbackCompleted() is called on the provided
        // HostFeedbackHandler. The provided HostLogger will be called to log informational notices,
        // including warnings.
        //
        // Warnings:
        // - Only one active upload is supported at a time. An ongoing upload will be cancelled if
        // this function is called again before it completes.
        // - An ongoing feedback upload started with startSendFeedback() should be stopped with
        // stopSendFeedback() before the process exits. This ensures that any underlying resources
        // are cleaned up; failing to do so may result in data store corruption or other undefined
        // behavior.
        // - PsiphonTunnel.startTunneling and startSendFeedback both make an attempt to migrate
        // persistent files from legacy locations in a one-time operation. If these functions are
        // called in parallel, then there is a chance that the migration attempts could execute at
        // the same time and result in non-fatal errors in one, or both, of the migration
        // operations.
        public void startSendFeedback(Context context, HostFeedbackHandler feedbackHandler, HostLogger logger,
                                      String feedbackConfigJson, String diagnosticsJson, String uploadPath,
                                      String clientPlatformPrefix, String clientPlatformSuffix) {
            workQueue.execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        // Adds fields used in feedback upload, e.g. client platform.
                        String psiphonConfig = buildPsiphonConfig(context, logger, feedbackConfigJson,
                                clientPlatformPrefix, clientPlatformSuffix, false, 0);

                        Psi.startSendFeedback(psiphonConfig, diagnosticsJson, uploadPath,
                                new PsiphonProviderFeedbackHandler() {
                                    @Override
                                    public void sendFeedbackCompleted(java.lang.Exception e) {
                                        try {
                                            callbackQueue.execute(new Runnable() {
                                                @Override
                                                public void run() {
                                                    feedbackHandler.sendFeedbackCompleted(e);
                                                }
                                            });
                                        } catch (RejectedExecutionException ignored) {
                                        }
                                    }
                                },
                                new PsiphonProviderNetwork() {
                                    @Override
                                    public long hasNetworkConnectivity() {
                                        boolean hasConnectivity = PsiphonTunnel.hasNetworkConnectivity(context);
                                        // TODO: change to bool return value once gobind supports that type
                                        return hasConnectivity ? 1 : 0;
                                    }

                                    @Override
                                    public String getNetworkID() {

                                        // startSendFeedback is invoked from the Psiphon UI process, not the Psiphon
                                        // VPN process.
                                        //
                                        // Case 1: no VPN is running
                                        //
                                        // isVpnMode = true/false doesn't change the network ID; the network ID will
                                        // be the physical network ID, and feedback may load existing tactics or may
                                        // fetch tactics.
                                        //
                                        // Case 2: Psiphon VPN is running
                                        //
                                        // In principle, we might want to set isVpnMode = true so that we obtain the
                                        // physical network ID and load any existing tactics. However, as the VPN
                                        // holds a lock on the data store, the load will fail; also no tactics request
                                        // is attempted.
                                        //
                                        // Hypothetically, if a tactics request did proceed, the tunneled client GeoIP
                                        // would not reflect the actual client location, and so it's safer to set
                                        // isVpnMode = false to ensure fetched tactics are stored under a distinct
                                        // Network ID ("VPN").
                                        //
                                        // Case 3: another VPN is running
                                        //
                                        // Unlike case 2, there's no Psiphon VPN process holding the data store lock.
                                        // As with case 2, there's some merit to setting isVpnMode = true in order to
                                        // load existing tactics, but since a tactics request may proceed, it's safer
                                        // to set isVpnMode = false and store fetched tactics under a distinct
                                        // Network ID ("VPN").

                                        return PsiphonTunnel.getNetworkID(context, false);
                                    }

                                    @Override
                                    public String iPv6Synthesize(String IPv4Addr) {
                                        // Unused on Android.
                                        return PsiphonTunnel.iPv6Synthesize(IPv4Addr);
                                    }

                                    @Override
                                    public long hasIPv6Route() {
                                        return PsiphonTunnel.hasIPv6Route(context, logger);
                                    }
                                },
                                new PsiphonProviderNoticeHandler() {
                                    @Override
                                    public void notice(String noticeJSON) {

                                        try {
                                            JSONObject notice = new JSONObject(noticeJSON);

                                            String noticeType = notice.getString("noticeType");
                                            if (noticeType == null) {
                                                return;
                                            }

                                            JSONObject data = notice.getJSONObject("data");
                                            if (data == null) {
                                                return;
                                            }

                                            String diagnosticMessage = noticeType + ": " + data.toString();
                                            try {
                                                callbackQueue.execute(new Runnable() {
                                                    @Override
                                                    public void run() {
                                                        logger.onDiagnosticMessage(diagnosticMessage);
                                                    }
                                                });
                                            } catch (RejectedExecutionException ignored) {
                                            }
                                        } catch (java.lang.Exception e) {
                                            try {
                                                callbackQueue.execute(new Runnable() {
                                                    @Override
                                                    public void run() {
                                                        logger.onDiagnosticMessage("Error handling notice " + e.toString());
                                                    }
                                                });
                                            } catch (RejectedExecutionException ignored) {
                                            }
                                        }
                                    }
                                },
                                false,   // Do not use IPv6 synthesizer for Android
                                true     // Use hasIPv6Route on Android
                                );
                    } catch (java.lang.Exception e) {
                        try {
                            callbackQueue.execute(new Runnable() {
                                @Override
                                public void run() {
                                    feedbackHandler.sendFeedbackCompleted(new Exception("Error sending feedback", e));
                                }
                            });
                        } catch (RejectedExecutionException ignored) {
                        }
                    }
                }
            });
        }

        // Interrupt an in-progress feedback upload operation started with startSendFeedback() and shutdown
        // executor queues.
        // NOTE: this instance cannot be reused after shutdown() has been called.
        public void shutdown() {
            workQueue.execute(new Runnable() {
                @Override
                public void run() {
                    Psi.stopSendFeedback();
                }
            });

            shutdownAndAwaitTermination(workQueue);
            shutdownAndAwaitTermination(callbackQueue);
        }
    }

    //----------------------------------------------------------------------------------------------
    // VPN Routing
    //----------------------------------------------------------------------------------------------

    private final static String VPN_INTERFACE_NETMASK = "255.255.255.0";
    private final static int VPN_INTERFACE_MTU = 1500;
    private final static int UDPGW_SERVER_PORT = 7300;

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

    @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    private ParcelFileDescriptor startDummyVpn(VpnService.Builder vpnServiceBuilder) throws Exception {
        PrivateAddress privateAddress = selectPrivateAddress();

        Locale previousLocale = Locale.getDefault();

        final String errorMessage = "startDummyVpn failed";
        final ParcelFileDescriptor tunFd;
        try {
            // Workaround for https://code.google.com/p/android/issues/detail?id=61096
            Locale.setDefault(new Locale("en"));

            int mtu = VPN_INTERFACE_MTU;
            String dnsResolver = privateAddress.mRouter;

            tunFd = vpnServiceBuilder
                            .setSession(mHostService.getAppName())
                            .setMtu(mtu)
                            .addAddress(privateAddress.mIpAddress, privateAddress.mPrefixLength)
                            .addRoute("0.0.0.0", 0)
                            .addRoute(privateAddress.mSubnet, privateAddress.mPrefixLength)
                            .addDnsServer(dnsResolver)
                            .establish();
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

        return tunFd;
    }

    private boolean isVpnMode() {
        return mVpnMode.get();
    }

    private void setLocalSocksProxyPort(int port) {
        mLocalSocksProxyPort.set(port);
    }

    private void stopVpn() {
        stopTun2Socks();
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

    // The PsiphonProvider functions are called from Go, and must be public to be accessible
    // via the gobind mechanim. To avoid making internal implementation functions public,
    // PsiphonProviderShim is used as a wrapper.

    private class PsiphonProviderShim implements PsiphonProvider {

        private PsiphonTunnel mPsiphonTunnel;

        public PsiphonProviderShim(PsiphonTunnel psiphonTunnel) {
            mPsiphonTunnel = psiphonTunnel;
        }

        @Override
        public void notice(String noticeJSON) {
            mPsiphonTunnel.notice(noticeJSON);
        }

        @Override
        public String bindToDevice(long fileDescriptor) throws Exception {
            return mPsiphonTunnel.bindToDevice(fileDescriptor);
        }

        @Override
        public long hasNetworkConnectivity() {
            return mPsiphonTunnel.hasNetworkConnectivity();
        }

        @Override
        public String getDNSServersAsString() {
            return mPsiphonTunnel.getDNSServers(mHostService.getContext(), mHostService);
        }

        @Override
        public String iPv6Synthesize(String IPv4Addr) {
            return PsiphonTunnel.iPv6Synthesize(IPv4Addr);
        }

        @Override
        public long hasIPv6Route() {
            return PsiphonTunnel.hasIPv6Route(mHostService.getContext(), mHostService);
        }

        @Override
        public String getNetworkID() {
            return PsiphonTunnel.getNetworkID(mHostService.getContext(), mPsiphonTunnel.isVpnMode());
        }
    }

    private void notice(String noticeJSON) {
        handlePsiphonNotice(noticeJSON);
    }

    @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    private String bindToDevice(long fileDescriptor) throws Exception {
        if (!((VpnService)mHostService.getVpnService()).protect((int)fileDescriptor)) {
            throw new Exception("protect socket failed");
        }
        return "";
    }

    private long hasNetworkConnectivity() {
        boolean hasConnectivity = hasNetworkConnectivity(mHostService.getContext());
        boolean wasWaitingForNetworkConnectivity = mIsWaitingForNetworkConnectivity.getAndSet(!hasConnectivity);
        // HasNetworkConnectivity may be called many times, but only invoke
        // callbacks once per loss or resumption of connectivity, so, e.g.,
        // the HostService may log a single message.
        if (!hasConnectivity && !wasWaitingForNetworkConnectivity) {
            mHostService.onStartedWaitingForNetworkConnectivity();
        } else if (hasConnectivity && wasWaitingForNetworkConnectivity) {
            mHostService.onStoppedWaitingForNetworkConnectivity();
        }
        // TODO: change to bool return value once gobind supports that type
        return hasConnectivity ? 1 : 0;
    }

    private String getDNSServers(Context context, HostLogger logger) {

        // Use the DNS servers set by mNetworkMonitor,
        // mActiveNetworkDNSServers, when available. It's the most reliable
        // mechanism. Otherwise fallback to getActiveNetworkDNSServers.
        //
        // mActiveNetworkDNSServers is not available on API < 21
        // (LOLLIPOP). mActiveNetworkDNSServers may also be temporarily
        // unavailable if the last active network has been lost and no new
        // one has yet replaced it.

        String servers = mActiveNetworkDNSServers.get();
        if (servers != "") {
            return servers;
        }

        try {
            // Use the workaround, comma-delimited format required for gobind.
            servers = TextUtils.join(",", getActiveNetworkDNSServers(context, mVpnMode.get()));
        } catch (Exception e) {
            logger.onDiagnosticMessage("failed to get active network DNS resolver: " + e.getMessage());
            // Alternate DNS servers will be provided by psiphon-tunnel-core
            // config or tactics.
        }
        return servers;
    }

    private static String iPv6Synthesize(String IPv4Addr) {
        // Unused on Android.
        return IPv4Addr;
    }

    private static long hasIPv6Route(Context context, HostLogger logger) {
        boolean hasRoute = false;
        try {
            hasRoute = hasIPv6Route(context);
        } catch (Exception e) {
            logger.onDiagnosticMessage("failed to check IPv6 route: " + e.getMessage());
        }
        // TODO: change to bool return value once gobind supports that type
        return hasRoute ? 1 : 0;
    }

    private static String getNetworkID(Context context, boolean isVpnMode) {

        // TODO: getActiveNetworkInfo is deprecated in API 29; once
        // getActiveNetworkInfo is no longer available, use
        // mActiveNetworkType which is updated by mNetworkMonitor.

        // The network ID contains potential PII. In tunnel-core, the network ID
        // is used only locally in the client and not sent to the server.
        //
        // See network ID requirements here:
        // https://godoc.org/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon#NetworkIDGetter

        String networkID = "UNKNOWN";

        ConnectivityManager connectivityManager = (ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (!isVpnMode) {
                NetworkCapabilities capabilities = null;
                try {
                    Network nw = connectivityManager.getActiveNetwork();
                    capabilities = connectivityManager.getNetworkCapabilities(nw);
                } catch (java.lang.Exception e)  {
                    // May get exceptions due to missing permissions like android.permission.ACCESS_NETWORK_STATE.

                    // Apps using the Psiphon Library and lacking android.permission.ACCESS_NETWORK_STATE will
                    // proceed and use tactics, but with "UNKNOWN" as the sole network ID.
                }

                if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    return "VPN";
                }
            }
        }

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
        mIsWaitingForNetworkConnectivity.set(false);
        mHostService.onDiagnosticMessage("starting Psiphon library");
        try {
            // mNetworkMonitor.start() will wait up to 1 second before returning to give the network
            // callback a chance to populate active network properties before we start the tunnel.
            mNetworkMonitor.start(mHostService.getContext());
            Psi.start(
                    loadPsiphonConfig(mHostService.getContext()),
                    embeddedServerEntries,
                    "",
                    new PsiphonProviderShim(this),
                    isVpnMode(),
                    false,   // Do not use IPv6 synthesizer for Android
                    true     // Use hasIPv6Route on Android
                    );
        } catch (java.lang.Exception e) {
            throw new Exception("failed to start Psiphon library", e);
        }

        mHostService.onDiagnosticMessage("Psiphon library started");
    }

    private void stopPsiphon() {
        mHostService.onDiagnosticMessage("stopping Psiphon library");
        mNetworkMonitor.stop(mHostService.getContext());
        Psi.stop();
        mHostService.onDiagnosticMessage("Psiphon library stopped");
    }

    private String loadPsiphonConfig(Context context)
            throws IOException, JSONException, Exception {

        return buildPsiphonConfig(context, mHostService, mHostService.getPsiphonConfig(),
                mClientPlatformPrefix.get(), mClientPlatformSuffix.get(), isVpnMode(),
                mLocalSocksProxyPort.get());
    }

    private static String buildPsiphonConfig(Context context, HostLogger logger, String psiphonConfig,
                                             String clientPlatformPrefix, String clientPlatformSuffix,
                                             boolean isVpnMode, Integer localSocksProxyPort)
            throws IOException, JSONException, Exception {

        // Load settings from the raw resource JSON config file and
        // update as necessary. Then write JSON to disk for the Go client.
        JSONObject json = new JSONObject(psiphonConfig);

        // On Android, this directory must be set to the app private storage area.
        // The Psiphon library won't be able to use its current working directory
        // and the standard temporary directories do not exist.
        if (!json.has("DataRootDirectory")) {
            File dataRootDirectory = defaultDataRootDirectory(context);
            if (!dataRootDirectory.exists()) {
                boolean created = dataRootDirectory.mkdir();
                if (!created) {
                    throw new Exception("failed to create data root directory: " + dataRootDirectory.getPath());
                }
            }
            json.put("DataRootDirectory", defaultDataRootDirectory(context));
        }

        // Migrate datastore files from legacy directory.
        if (!json.has("DataStoreDirectory")) {
            json.put("MigrateDataStoreDirectory", context.getFilesDir());
        }

        // Migrate remote server list downloads from legacy location.
        if (!json.has("RemoteServerListDownloadFilename")) {
            File remoteServerListDownload = new File(context.getFilesDir(), "remote_server_list");
            json.put("MigrateRemoteServerListDownloadFilename", remoteServerListDownload.getAbsolutePath());
        }

        // Migrate obfuscated server list download files from legacy directory.
        File oslDownloadDir = new File(context.getFilesDir(), "osl");
        json.put("MigrateObfuscatedServerListDownloadDirectory", oslDownloadDir.getAbsolutePath());

        // Continue to run indefinitely until connected
        if (!json.has("EstablishTunnelTimeoutSeconds")) {
            json.put("EstablishTunnelTimeoutSeconds", 0);
        }

        json.put("EmitBytesTransferred", true);

        if (localSocksProxyPort != 0 && (!json.has("LocalSocksProxyPort") || json.getInt("LocalSocksProxyPort") == 0)) {
            // When mLocalSocksProxyPort is set, tun2socks is already configured
            // to use that port value. So we force use of the same port.
            // A side-effect of this is that changing the SOCKS port preference
            // has no effect with restartPsiphon(), a full stop() is necessary.
            json.put("LocalSocksProxyPort", localSocksProxyPort);
        }

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
            try {
                json.put(
                        "TrustedCACertificatesFilename",
                        setupTrustedCertificates(context, logger));
            } catch (Exception e) {
                logger.onDiagnosticMessage(e.getMessage());
            }
        }

        json.put("DeviceRegion", getDeviceRegion(context));

        StringBuilder clientPlatform = new StringBuilder();

        if (clientPlatformPrefix.length() > 0) {
            clientPlatform.append(clientPlatformPrefix);
        }

        clientPlatform.append("Android_");
        clientPlatform.append(Build.VERSION.RELEASE);
        clientPlatform.append("_");
        clientPlatform.append(context.getPackageName());

        if (clientPlatformSuffix.length() > 0) {
            clientPlatform.append(clientPlatformSuffix);
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
                if (count == 0) {
                    mHostService.onConnecting();
                } else if (count == 1) {
                    if (isVpnMode() && mShouldRouteThroughTunnelAutomatically) {
                        routeThroughTunnel();
                    }
                    mHostService.onConnected();
                }
                // count > 1 is an additional multi-tunnel establishment, and not reported.

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
                diagnostic = false;
                mHostService.onUpstreamProxyError(notice.getJSONObject("data").getString("message"));
            } else if (noticeType.equals("ClientUpgradeDownloaded")) {
                mHostService.onClientUpgradeDownloaded(notice.getJSONObject("data").getString("filename"));
            } else if (noticeType.equals("ClientIsLatestVersion")) {
                mHostService.onClientIsLatestVersion();
            } else if (noticeType.equals("Homepage")) {
                mHostService.onHomepage(notice.getJSONObject("data").getString("url"));
            } else if (noticeType.equals("ClientRegion")) {
                mHostService.onClientRegion(notice.getJSONObject("data").getString("region"));
            } else if (noticeType.equals("ClientAddress")) {
                diagnostic = false;
                mHostService.onClientAddress(notice.getJSONObject("data").getString("address"));
            } else if (noticeType.equals("SplitTunnelRegions")) {
                JSONArray splitTunnelRegions = notice.getJSONObject("data").getJSONArray("regions");
                ArrayList<String> regions = new ArrayList<String>();
                for (int i=0; i<splitTunnelRegions.length(); i++) {
                    regions.add(splitTunnelRegions.getString(i));
                }
                mHostService.onSplitTunnelRegions(regions);
            } else if (noticeType.equals("Untunneled")) {
                diagnostic = false;
                mHostService.onUntunneledAddress(notice.getJSONObject("data").getString("address"));
            } else if (noticeType.equals("BytesTransferred")) {
                diagnostic = false;
                JSONObject data = notice.getJSONObject("data");
                mHostService.onBytesTransferred(data.getLong("sent"), data.getLong("received"));
            } else if (noticeType.equals("ActiveAuthorizationIDs")) {
                JSONArray activeAuthorizationIDs = notice.getJSONObject("data").getJSONArray("IDs");
                ArrayList<String> authorizations = new ArrayList<String>();
                for (int i=0; i<activeAuthorizationIDs.length(); i++) {
                    authorizations.add(activeAuthorizationIDs.getString(i));
                }
                mHostService.onActiveAuthorizationIDs(authorizations);
            } else if (noticeType.equals("TrafficRateLimits")) {
                JSONObject data = notice.getJSONObject("data");
                mHostService.onTrafficRateLimits(
                    data.getLong("upstreamBytesPerSecond"), data.getLong("downstreamBytesPerSecond"));
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
            } else if (noticeType.equals("ConnectedServerRegion")) {
                mHostService.onConnectedServerRegion(
                        notice.getJSONObject("data").getString("serverRegion"));
            } else if (noticeType.equals("ApplicationParameters")) {
                mHostService.onApplicationParameters(
                    notice.getJSONObject("data").get("parameters"));
            } else if (noticeType.equals("ServerAlert")) {
                JSONArray actionURLs = notice.getJSONObject("data").getJSONArray("actionURLs");
                ArrayList<String> actionURLsList = new ArrayList<String>();
                for (int i=0; i<actionURLs.length(); i++) {
                    actionURLsList.add(actionURLs.getString(i));
                }
                mHostService.onServerAlert(
                    notice.getJSONObject("data").getString("reason"),
                    notice.getJSONObject("data").getString("subject"),
                    actionURLsList);
            } else if (noticeType.equals("InproxyMustUpgrade")) {
                mHostService.onInproxyMustUpgrade();
            } else if (noticeType.equals("InproxyProxyActivity")) {
                JSONObject data = notice.getJSONObject("data");
                mHostService.onInproxyProxyActivity(
                        data.getInt("connectingClients"),
                        data.getInt("connectedClients"),
                        data.getLong("bytesUp"),
                        data.getLong("bytesDown"));
            }

            if (diagnostic) {
                String diagnosticMessage = noticeType + ": " + notice.getJSONObject("data").toString();
                mHostService.onDiagnosticMessage(diagnosticMessage);
            }

        } catch (JSONException e) {
            // Ignore notice
        }
    }

    private static String setupTrustedCertificates(Context context, HostLogger logger) throws Exception {

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

                logger.onDiagnosticMessage("prepared PsiphonCAStore");

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
            // getNetworkCountryIso, when present, is preferred over
            // getSimCountryIso, since getNetworkCountryIso is the network
            // the device is currently on, while getSimCountryIso is the home
            // region of the SIM. While roaming, only getNetworkCountryIso
            // may more accurately represent the actual device region.
            if (telephonyManager.getPhoneType() != TelephonyManager.PHONE_TYPE_CDMA) {
                region = telephonyManager.getNetworkCountryIso();
                if (region == null) {
                    region = "";
                }
            }
            if (region.length() == 0) {
                region = telephonyManager.getSimCountryIso();
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

        Enumeration<NetworkInterface> netInterfaces;
        try {
            netInterfaces = NetworkInterface.getNetworkInterfaces();
        } catch (SocketException e) {
            throw new Exception("selectPrivateAddress failed", e);
        }

        if (netInterfaces == null) {
            throw new Exception("no network interfaces found");
        }

        for (NetworkInterface netInterface : Collections.list(netInterfaces)) {
            for (InetAddress inetAddress : Collections.list(netInterface.getInetAddresses())) {
                if (inetAddress instanceof Inet4Address) {
                    String ipAddress = inetAddress.getHostAddress();
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

    private static Collection<String> getActiveNetworkDNSServers(Context context, boolean isVpnMode)
            throws Exception {

        ArrayList<String> servers = new ArrayList<String>();
        for (InetAddress serverAddress : getActiveNetworkDNSServerAddresses(context, isVpnMode)) {
            String server = serverAddress.toString();
            // strip the leading slash e.g., "/192.168.1.1"
            if (server.startsWith("/")) {
                server = server.substring(1);
            }
            servers.add(server);
        }

        if (servers.isEmpty()) {
            throw new Exception("no active network DNS resolver");
        }

        return servers;
    }

    private static Collection<InetAddress> getActiveNetworkDNSServerAddresses(Context context, boolean isVpnMode)
            throws Exception {

        final String errorMessage = "getActiveNetworkDNSServerAddresses failed";
        ArrayList<InetAddress> dnsAddresses = new ArrayList<InetAddress>();

        ConnectivityManager connectivityManager =
                (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivityManager == null) {
            throw new Exception(errorMessage, new Throwable("couldn't get ConnectivityManager system service"));
        }

        try {

            // Hidden API:
            //
            // - Only available in Android 4.0+
            // - No guarantee will be available beyond 4.2, or on all vendor
            //   devices
            // - Field reports indicate this is no longer working on some --
            //   but not all -- Android 10+ devices

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
        } catch (NoSuchMethodException e) {
        } catch (IllegalArgumentException e) {
        } catch (IllegalAccessException e) {
        } catch (InvocationTargetException e) {
        } catch (NullPointerException e) {
        }

        if (!dnsAddresses.isEmpty()) {
            return dnsAddresses;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {

            // This case is attempted only when the hidden API fails:
            //
            // - Testing shows the hidden API still works more reliably on
            //   some Android 11+ devices
            // - Testing indicates that the NetworkRequest can sometimes
            //   select the wrong network
            //   - e.g., mobile instead of WiFi, and return the wrong DNS
            //     servers
            //   - there's currently no way to filter for the "currently
            //     active default data network" returned by, e.g., the
            //     deprecated getActiveNetworkInfo
            //   - we cannot add the NET_CAPABILITY_FOREGROUND capability to
            //     the NetworkRequest at this time due to target SDK
            //     constraints

            NetworkRequest.Builder networkRequestBuilder = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);

            if (isVpnMode) {
                // In VPN mode, we want the DNS servers for the underlying physical network.
                networkRequestBuilder.addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
            }

            NetworkRequest networkRequest = networkRequestBuilder.build();

            // There is a potential race condition in which the following
            // network callback may be invoked, by a worker thread, after
            // unregisterNetworkCallback. Synchronized access to a local
            // ArrayList copy avoids the
            // java.util.ConcurrentModificationException crash we previously
            // observed when getActiveNetworkDNSServers iterated over the
            // same ArrayList object value that was modified by the
            // callback.
            //
            // The late invocation of the callback still results in an empty
            // list of DNS servers, but this behavior has been observed only
            // in artificial conditions while rapidly starting and stopping
            // PsiphonTunnel.

            ArrayList<InetAddress> callbackDnsAddresses = new ArrayList<InetAddress>();

            final CountDownLatch countDownLatch = new CountDownLatch(1);
            try {
                ConnectivityManager.NetworkCallback networkCallback =
                        new ConnectivityManager.NetworkCallback() {
                            @Override
                            public void onLinkPropertiesChanged(Network network,
                                                                LinkProperties linkProperties) {
                                synchronized (callbackDnsAddresses) {
                                    callbackDnsAddresses.addAll(linkProperties.getDnsServers());
                                }
                                countDownLatch.countDown();
                            }
                        };

                connectivityManager.registerNetworkCallback(networkRequest, networkCallback);
                countDownLatch.await(1, TimeUnit.SECONDS);
                connectivityManager.unregisterNetworkCallback(networkCallback);
            } catch (RuntimeException ignored) {
                // Failed to register network callback
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            synchronized (callbackDnsAddresses) {
                dnsAddresses.addAll(callbackDnsAddresses);
            }
        }

        return dnsAddresses;
    }

    private static boolean hasIPv6Route(Context context) throws Exception {

            try {
                // This logic mirrors the logic in
                // psiphon/common/resolver.hasRoutableIPv6Interface. That
                // function currently doesn't work on Android due to Go's
                // net.InterfaceAddrs failing on Android SDK 30+ (see Go issue
                // 40569). hasIPv6Route provides the same functionality via a
                // callback into Java code.

                // Note: don't exclude interfaces with the isPointToPoint
                // property, which is true for certain mobile networks.

                for (NetworkInterface netInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                    if (netInterface.isUp() &&
                        !netInterface.isLoopback()) {
                        for (InetAddress address : Collections.list(netInterface.getInetAddresses())) {

                            // Per https://developer.android.com/reference/java/net/Inet6Address#textual-representation-of-ip-addresses,
                            // "Java will never return an IPv4-mapped address.
                            //  These classes can take an IPv4-mapped address as
                            //  input, both in byte array and text
                            //  representation. However, it will be converted
                            //  into an IPv4 address." As such, when the type of
                            //  the IP address is Inet6Address, this should be
                            //  an actual IPv6 address.

                            if (address instanceof Inet6Address &&
                                !address.isLinkLocalAddress() &&
                                !address.isSiteLocalAddress() &&
                                !address.isMulticastAddress ()) {
                                return true;
                            }
                        }
                    }
                }
                } catch (SocketException e) {
                throw new Exception("hasIPv6Route failed", e);
            }

            return false;
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

    //----------------------------------------------------------------------------------------------
    // Network connectivity monitor
    //----------------------------------------------------------------------------------------------

    private static class NetworkMonitor {
        private final NetworkChangeListener listener;
        private ConnectivityManager.NetworkCallback networkCallback;
        public NetworkMonitor(
            NetworkChangeListener listener) {
            this.listener = listener;
        }

        private void start(Context context) throws InterruptedException {
            final CountDownLatch setNetworkPropertiesCountDownLatch = new CountDownLatch(1);

            // Need API 21(LOLLIPOP)+ for ConnectivityManager.NetworkCallback
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
                return;
            }
            ConnectivityManager connectivityManager =
                    (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (connectivityManager == null) {
                return;
            }
            networkCallback = new ConnectivityManager.NetworkCallback() {
                private boolean isInitialState = true;
                private Network currentActiveNetwork;

                private void consumeActiveNetwork(Network network) {
                    if (isInitialState) {
                        isInitialState = false;
                        setCurrentActiveNetworkAndProperties(network);
                        return;
                    }

                    if (!network.equals(currentActiveNetwork)) {
                        setCurrentActiveNetworkAndProperties(network);
                        if (listener != null) {
                            listener.onChanged();
                        }
                    }
                }

                private void consumeLostNetwork(Network network) {
                    if (network.equals(currentActiveNetwork)) {
                        setCurrentActiveNetworkAndProperties(null);
                        if (listener != null) {
                            listener.onChanged();
                        }
                    }
                }

                private void setCurrentActiveNetworkAndProperties(Network network) {

                    currentActiveNetwork = network;

                    if (network == null) {

                        mPsiphonTunnel.mActiveNetworkType.set("NONE");
                        mPsiphonTunnel.mActiveNetworkDNSServers.set("");
                        mPsiphonTunnel.mHostService.onDiagnosticMessage("NetworkMonitor: clear current active network");

                    } else {

                        String networkType = "UNKNOWN";
                        try {
                            // Limitation: a network may have both CELLULAR
                            // and WIFI transports, or different network
                            // transport types entirely. This logic currently
                            // mimics the type determination logic in
                            // getNetworkID.
                            NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(network);
                            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                                networkType = "VPN";
                            } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                                networkType = "MOBILE";
                            } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                                networkType = "WIFI";
                            }
                        } catch (java.lang.Exception e) {
                        }
                        mPsiphonTunnel.mActiveNetworkType.set(networkType);

                        ArrayList<String> servers = new ArrayList<String>();
                        try {
                            LinkProperties linkProperties = connectivityManager.getLinkProperties(network);
                            List<InetAddress> serverAddresses = linkProperties.getDnsServers();
                            for (InetAddress serverAddress : serverAddresses) {
                                String server = serverAddress.toString();
                                if (server.startsWith("/")) {
                                    server = server.substring(1);
                                }
                                servers.add(server);
                            }
                        } catch (java.lang.Exception e) {
                        }
                        // Use the workaround, comma-delimited format required for gobind.
                        mPsiphonTunnel.mActiveNetworkDNSServers.set(TextUtils.join(",", servers));

                        String message = "NetworkMonitor: set current active network " + networkType;
                        if (!servers.isEmpty()) {
                            // The DNS server address is potential PII and not logged.
                            message += " with DNS";
                        }
                        mPsiphonTunnel.mHostService.onDiagnosticMessage(message);
                    }
                    setNetworkPropertiesCountDownLatch.countDown();
                }

                @Override
                public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
                    super.onCapabilitiesChanged(network, capabilities);

                    // Need API 23(M)+ for NET_CAPABILITY_VALIDATED
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                        return;
                    }

                    // https://developer.android.com/reference/android/net/NetworkCapabilities#NET_CAPABILITY_VALIDATED
                    // Indicates that connectivity on this network was successfully validated.
                    // For example, for a network with NET_CAPABILITY_INTERNET, it means that Internet connectivity was
                    // successfully detected.
                    if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                        consumeActiveNetwork(network);
                    }
                }

                @Override
                public void onAvailable(Network network) {
                    super.onAvailable(network);

                    // Skip on API 26(O)+ because onAvailable is guaranteed to be followed by
                    // onCapabilitiesChanged
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        return;
                    }
                    consumeActiveNetwork(network);
                }

                @Override
                public void onLost(Network network) {
                    super.onLost(network);
                    consumeLostNetwork(network);
                }
            };

            try {
                // When searching for a network to satisfy a request, all capabilities requested must be satisfied.
                NetworkRequest.Builder builder = new NetworkRequest.Builder()
                        // Indicates that this network should be able to reach the internet.
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);

                if (mPsiphonTunnel.mVpnMode.get()) {
                    // If we are in the VPN mode then ensure we monitor only the VPN's underlying
                    // active networks and not self.
                    builder.addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
                } else {
                    // If we are NOT in the VPN mode then monitor default active networks with the
                    // Internet capability, including VPN, to ensure we won't trigger a reconnect in
                    // case the VPN is up while the system switches the underlying network.

                    // Limitation: for Psiphon Library apps running over Psiphon VPN, or other VPNs
                    // with a similar architecture, it may be better to trigger a reconnect when
                    // the underlying physical network changes. When the underlying network
                    // changes, Psiphon VPN will remain up and reconnect its own tunnel. For the
                    // Psiphon app, this monitoring will detect no change. However, the Psiphon
                    // app's tunnel may be lost, and, without network change detection, initiating
                    // a reconnect will be delayed. For example, if the Psiphon app's tunnel is
                    // using QUIC, the Psiphon VPN will tunnel that traffic over udpgw. When
                    // Psiphon VPN reconnects, the egress source address of that UDP flow will
                    // change -- getting either a different source IP if the Psiphon server
                    // changes, or a different source port even if the same server -- and the QUIC
                    // server will drop the packets. The Psiphon app will initiate a reconnect only
                    // after a SSH keep alive probes timeout or a QUIC timeout.
                    //
                    // TODO: Add a second ConnectivityManager/NetworkRequest instance to monitor
                    // for underlying physical network changes while any VPN remains up.

                    builder.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
                }

                NetworkRequest networkRequest = builder.build();
                // We are using requestNetwork and not registerNetworkCallback here because we found
                // that the callbacks from requestNetwork are more accurate in terms of tracking
                // currently active network. Another alternative to use for tracking active network
                // would be registerDefaultNetworkCallback but a) it needs API >= 24 and b) doesn't
                // provide a way to set up monitoring of underlying networks only when VPN transport
                // is also active.
                connectivityManager.requestNetwork(networkRequest, networkCallback);
            } catch (RuntimeException ignored) {
                // Could be a security exception or any other runtime exception on customized firmwares.
                networkCallback = null;
            }
            // We are going to wait up to one second for the network callback to populate
            // active network properties before returning.
            setNetworkPropertiesCountDownLatch.await(1, TimeUnit.SECONDS);
        }

        private void stop(Context context) {
            if (networkCallback == null) {
                return;
            }
            // Need API 21(LOLLIPOP)+ for ConnectivityManager.NetworkCallback
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
                return;
            }
            ConnectivityManager connectivityManager =
                    (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (connectivityManager == null) {
                return;
            }
            // Note: ConnectivityManager.unregisterNetworkCallback() may throw
            // "java.lang.IllegalArgumentException: NetworkCallback was not registered".
            // This scenario should be handled in the start() above but we'll add a try/catch
            // anyway to match the start's call to ConnectivityManager.registerNetworkCallback()
            try {
                connectivityManager.unregisterNetworkCallback(networkCallback);
            } catch (RuntimeException ignored) {
            }
            networkCallback = null;
        }

        public interface NetworkChangeListener {
            void onChanged();
        }
    }
}
