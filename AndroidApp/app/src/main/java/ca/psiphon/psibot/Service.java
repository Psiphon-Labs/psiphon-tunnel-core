/*
 * Copyright (c) 2014, Psiphon Inc.
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

package ca.psiphon.psibot;

import android.app.Notification;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.preference.PreferenceManager;

import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class Service extends VpnService
        implements SharedPreferences.OnSharedPreferenceChangeListener {

    // Note: assumes only one instance of Service
    private static AtomicBoolean mIsRunning = new AtomicBoolean();

    public static boolean isRunning() {
        return mIsRunning.get();
    }

    private Thread mThread;
    private CountDownLatch mInterruptSignal;
    private AtomicBoolean mStopFlag;

    @Override
    public void onCreate() {
        mIsRunning.set(true);
        startForeground(R.string.foregroundServiceNotificationId, makeForegroundNotification());
        startWorking();
        PreferenceManager.getDefaultSharedPreferences(this).
                registerOnSharedPreferenceChangeListener(this);
    }

    @Override
    public void onDestroy() {
        PreferenceManager.getDefaultSharedPreferences(this).
                unregisterOnSharedPreferenceChangeListener(this);
        stopWorking();
        stopForeground(true);
        mIsRunning.set(false);
    }

    @Override
    public synchronized void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
        if (!mIsRunning.get()) {
            return;
        }
        // An interrupt without setting stop will restart Psiphon, using the newest preferences.
        interruptWorking();
    }

    private void startWorking() {
        stopWorking();
        mInterruptSignal = new CountDownLatch(1);
        mStopFlag = new AtomicBoolean(false);
        mThread = new Thread(new Runnable() {
            @Override
            public void run() {
                CountDownLatch tunnelStartedSignal = new CountDownLatch(1);
                Psiphon psiphon = new Psiphon(Service.this, tunnelStartedSignal);
                // An interrupt with mStopFlag=false will cause Psiphon to restart without stopping
                // the service thread or VPN; this is to apply new preferences to the Psiphon config.
                // (The VPN is restarted if the preferred SOCKS proxy port changes.)
                int localSocksProxyPort = -1;
                while (!mStopFlag.get()) {
                    try {
                        // TODO: monitor tunnel messages and update notification UI when re-connecting, etc.
                        psiphon.start();
                        while (true) {
                            if (tunnelStartedSignal.await(100, TimeUnit.MILLISECONDS)) {
                                break;
                            }
                            if (mInterruptSignal.await(0, TimeUnit.MILLISECONDS)) {
                                throw new Utils.PsibotError("interrupted while waiting tunnel");
                            }
                        }
                        // [Re]start the VPN when the local SOCKS proxy port changes. Leave the
                        // VPN up when other preferences change; only Psiphon restarts in this case.
                        if (psiphon.getLocalSocksProxyPort() != localSocksProxyPort) {
                            if (localSocksProxyPort != -1) {
                                stopVpn();
                            }
                            localSocksProxyPort = psiphon.getLocalSocksProxyPort();
                            runVpn(localSocksProxyPort);
                        }
                        mInterruptSignal.await();
                    } catch (Utils.PsibotError e) {
                        Log.addEntry("Service failed: " + e.getMessage());
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                stopVpn();
                psiphon.stop();
                stopSelf();
            }
        });
        mThread.start();
    }

    private void interruptWorking() {
        if (mInterruptSignal == null) {
            return;
        }
        CountDownLatch currentSignal = mInterruptSignal;
        // This is the new interrupt signal for when work resumes
        mInterruptSignal = new CountDownLatch(1);
        // Interrupt work
        currentSignal.countDown();
    }

    private void stopWorking() {
        if (mStopFlag != null) {
            mStopFlag.set(true);
        }
        interruptWorking();
        if (mThread != null) {
            try {
                mThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        mInterruptSignal = null;
        mStopFlag = null;
        mThread = null;
    }

    private final static String VPN_INTERFACE_NETMASK = "255.255.255.0";
    private final static int VPN_INTERFACE_MTU = 1500;
    private final static int UDPGW_SERVER_PORT = 7300;

    private void runVpn(int localSocksProxyPort) throws Utils.PsibotError {
        Log.addEntry("network type: " + Utils.getNetworkTypeName(this));

        String privateIpAddress = Utils.selectPrivateAddress();
        if (privateIpAddress == null) {
            throw new Utils.PsibotError("no private address available");
        }

        ParcelFileDescriptor vpnInterfaceFileDescriptor = establishVpn(privateIpAddress);
        Log.addEntry("VPN established");

        String socksServerAddress = "127.0.0.1:" + Integer.toString(localSocksProxyPort);
        String udpgwServerAddress = "127.0.0.1:" + Integer.toString(UDPGW_SERVER_PORT);
        Tun2Socks.start(
                this,
                vpnInterfaceFileDescriptor,
                VPN_INTERFACE_MTU,
                Utils.getPrivateAddressRouter(privateIpAddress),
                VPN_INTERFACE_NETMASK,
                socksServerAddress,
                udpgwServerAddress,
                true);
        Log.addEntry("tun2socks started");

        // Note: should now double-check tunnel routing; see:
        // https://bitbucket.org/psiphon/psiphon-circumvention-system/src/1dc5e4257dca99790109f3bf374e8ab3a0ead4d7/Android/PsiphonAndroidLibrary/src/com/psiphon3/psiphonlibrary/TunnelCore.java?at=default#cl-779
    }

    private ParcelFileDescriptor establishVpn(String privateIpAddress)
        throws Utils.PsibotError {

        Locale previousLocale = Locale.getDefault();
        ParcelFileDescriptor vpnInterfaceFileDescriptor = null;

        final String errorMessage = "establishVpn failed";
        try {
            String subnet = Utils.getPrivateAddressSubnet(privateIpAddress);
            int prefixLength = Utils.getPrivateAddressPrefixLength(privateIpAddress);
            String router = Utils.getPrivateAddressRouter(privateIpAddress);

            // Set the locale to English (or probably any other language that
            // uses Hindu-Arabic (aka Latin) numerals).
            // We have found that VpnService.Builder does something locale-dependent
            // internally that causes errors when the locale uses its own numerals
            // (i.e., Farsi and Arabic).
            Locale.setDefault(new Locale("en"));

            vpnInterfaceFileDescriptor = new VpnService.Builder()
                    .setSession(getString(R.string.app_name))
                    .setMtu(VPN_INTERFACE_MTU)
                    .addAddress(privateIpAddress, prefixLength)
                    .addRoute("0.0.0.0", 0)
                    .addRoute(subnet, prefixLength)
                    .addDnsServer(router)
                    .establish();

            if (vpnInterfaceFileDescriptor == null) {
                // as per http://developer.android.com/reference/android/net/VpnService.Builder.html#establish%28%29
                throw new Utils.PsibotError(errorMessage + ": application is not prepared or is revoked");
            }
        } catch(IllegalArgumentException e) {
            throw new Utils.PsibotError(errorMessage, e);
        } catch(IllegalStateException e) {
            throw new Utils.PsibotError(errorMessage, e);
        } catch(SecurityException e) {
            throw new Utils.PsibotError(errorMessage, e);
        } finally {
            // Restore the original locale.
            Locale.setDefault(previousLocale);
        }

        return vpnInterfaceFileDescriptor;
    }

    private void stopVpn() {
        // Tun2socks closes the VPN file descriptor, which closes the VpnService session
        Tun2Socks.stop();
        Log.addEntry("VPN stopped");
    }

    private Notification makeForegroundNotification() {
        Intent intent = new Intent(this, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.setAction("android.intent.action.MAIN");
        PendingIntent pendingIntent =
                PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);

        Notification.Builder notificationBuilder =
                new Notification.Builder(this)
                        .setContentIntent(pendingIntent)
                        .setContentTitle(getString(R.string.foreground_service_notification_content_title))
                        .setSmallIcon(R.drawable.ic_notification);

        return notificationBuilder.build();
    }
}
