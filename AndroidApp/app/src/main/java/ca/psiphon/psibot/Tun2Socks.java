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

import android.content.Context;
import android.content.Intent;
import android.os.ParcelFileDescriptor;

import java.util.concurrent.atomic.AtomicBoolean;

public class Tun2Socks {

    // Note: can't run more than one tun2socks instance due to the use of
    // global state (the lwip module, etc.) in the native code.

    // Note: assumes only one instance of Tun2Socks
    private static Thread mThread;
    private static AtomicBoolean mIsRunning = new AtomicBoolean();

    public static synchronized void start(
            final Context context,
            final ParcelFileDescriptor vpnInterfaceFileDescriptor,
            final int vpnInterfaceMTU,
            final String vpnIpAddress,
            final String vpnNetMask,
            final String socksServerAddress,
            final String udpgwServerAddress,
            final boolean udpgwTransparentDNS) {
        stop();
        mThread = new Thread(new Runnable() {
            @Override
            public void run() {
                mIsRunning.set(true);
                runTun2Socks(
                        vpnInterfaceFileDescriptor.detachFd(),
                        vpnInterfaceMTU,
                        vpnIpAddress,
                        vpnNetMask,
                        socksServerAddress,
                        udpgwServerAddress,
                        udpgwTransparentDNS ? 1 : 0);
            	
                if (!mIsRunning.get()) {
                    Log.addEntry("Tun2Socks: unexpected termination");
                    context.stopService(new Intent(context, Service.class));
                }
            }
        });
        mThread.start();
    }
    
    public static synchronized void stop() {
        if (mThread != null) {
            terminateTun2Socks();
            try {
                mThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            mThread = null;
            mIsRunning.set(false);
        }
    }
        
    public static void logTun2Socks(String level, String channel, String msg) {
        String logMsg = "Tun2Socks: " + level + "(" + channel + "): " + msg;
        Log.addEntry(logMsg);
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
    
    static
    {
        System.loadLibrary("tun2socks");
    }
}
