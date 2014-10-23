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

import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class SocketProtector {

    final private VpnService mVpnService;
    private LocalServerSocket mLocalServerSocket;
    private Thread mThread;

    // Note: must match value in app\src\main\res\raw\psiphon.config
    public static final String SOCKET_PROTECTOR_ADDRESS = "/psibot/socketProtector";

    public SocketProtector(VpnService vpnService) {
        mVpnService = vpnService;
    }

    public void start() throws Utils.PsibotError {
        stop();
        try {
            mLocalServerSocket = new LocalServerSocket(SOCKET_PROTECTOR_ADDRESS);
        } catch (IOException e) {
            throw new Utils.PsibotError("failed to start socket protector", e);
        }
        mThread = new Thread(new Runnable() {
            @Override
            public void run() {
                String stoppingMessage = "socket protector stopping";
                try {
                    LocalSocket socket = mLocalServerSocket.accept();
                    // TODO: need to do a read()?
                    for (FileDescriptor fileDescriptor : socket.getAncillaryFileDescriptors()) {
                        protectSocket(fileDescriptor);
                    }
                } catch (Utils.PsibotError e) {
                    stoppingMessage += ": " + e.getMessage();
                } catch (IOException e) {
                    stoppingMessage += ": " + e.getMessage();
                }
                Log.addEntry(stoppingMessage);
            }
        });
        mThread.start();
        Log.addEntry("socket protector started");
    }

    public void stop() {
        if (mLocalServerSocket != null) {
            try {
                mLocalServerSocket.close();
            } catch (IOException e) {
            }
        }
        if (mThread != null) {
            try {
                mThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        mLocalServerSocket = null;
        mThread = null;
    }

    private void protectSocket(FileDescriptor fileDescriptor) throws Utils.PsibotError {
        // Based on this code:
        // https://code.google.com/p/ics-openvpn/source/browse/main/src/main/java/de/blinkt/openvpn/core/OpenVpnManagementThread.java#164
        /*
         * Copyright (c) 2012-2014 Arne Schwabe
         * Distributed under the GNU GPL v2. For full terms see the file doc/LICENSE.txt
         */
        final String errorMessage = "failed to protect socket";
        try {
            Method getInt = FileDescriptor.class.getDeclaredMethod("getInt$");
            int fd = (Integer) getInt.invoke(fileDescriptor);
            if (!mVpnService.protect(fd)) {
                throw new Utils.PsibotError(errorMessage);
            }
            ParcelFileDescriptor.fromFd(fd).close();
            // TODO: NativeUtils.jniclose(fdint); ...?
        } catch (NoSuchMethodException e) {
            throw new Utils.PsibotError(errorMessage, e);
        } catch (IllegalArgumentException e) {
            throw new Utils.PsibotError(errorMessage, e);
        } catch (IllegalAccessException e) {
            throw new Utils.PsibotError(errorMessage, e);
        } catch (InvocationTargetException e) {
            throw new Utils.PsibotError(errorMessage, e);
        } catch (NullPointerException e) {
            throw new Utils.PsibotError(errorMessage, e);
        } catch (IOException e) {
            throw new Utils.PsibotError(errorMessage, e);
        }
    }
}
