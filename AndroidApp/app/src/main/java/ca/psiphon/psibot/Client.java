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
import android.os.Build;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

public class Client {

    private final Context mContext;
    private final CountDownLatch mTunnelStartedSignal;
    private File mRootDirectory;
    private File mExecutableFile;
    private File mConfigFile;
    private Process mProcess;
    private Thread mStdoutThread;
    private int mLocalSocksProxyPort;
    private int mLocalHttpProxyPort;
    private List<String> mHomePages;

    public Client(Context context, CountDownLatch tunnelStartedSignal) {
        mContext = context;
        mTunnelStartedSignal = tunnelStartedSignal;
    }

    public void start() throws Utils.PsibotError {
        stop();
        prepareFiles();

        try {
            mProcess = new ProcessBuilder(
                    mExecutableFile.getAbsolutePath(),
                    "--config", mConfigFile.getAbsolutePath())
                    .directory(mRootDirectory)
                    .redirectErrorStream(true)
                    .start();
        } catch (IOException e) {
            throw new Utils.PsibotError("failed to start client process", e);
        }

        mStdoutThread = new Thread(new Runnable() {
            @Override
            public void run() {
                consumeStream(mProcess.getInputStream());
                Log.addEntry("Psiphon client stopping");
            }
        });
        mStdoutThread.start();

        mLocalSocksProxyPort = 0;
        mLocalHttpProxyPort = 0;
        mHomePages = new ArrayList<String>();

        Log.addEntry("Psiphon client started");
    }

    public void stop() {
        if (mProcess != null) {
            mProcess.destroy();
            try {
                mProcess.waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            Log.addEntry("Psiphon client stopped");
        }
        if (mStdoutThread != null) {
            try {
                mStdoutThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        mProcess = null;
        mStdoutThread = null;
    }

    public synchronized int getLocalSocksProxyPort() {
        return mLocalSocksProxyPort;
    }

    public synchronized int getLocalHttpProxyPort() {
        return mLocalHttpProxyPort;
    }

    public synchronized List<String> getHomePages() {
        return mHomePages != null ? new ArrayList<String>(mHomePages) : new ArrayList<String>();
    }

    private void prepareFiles() throws Utils.PsibotError {
        mRootDirectory = mContext.getDir("psiphon_tunnel_core", Context.MODE_PRIVATE);
        mExecutableFile = new File(mRootDirectory, "psiphon_tunnel_core");
        mConfigFile = new File(mRootDirectory, "psiphon_config");
        if (0 != Build.CPU_ABI.compareTo("armeabi-v7a")) {
            throw new Utils.PsibotError("no client binary for this CPU");
        }
        try {
            Utils.writeRawResourceFile(mContext, R.raw.psiphon_tunnel_core_arm, mExecutableFile, true);
            Utils.writeRawResourceFile(mContext, R.raw.psiphon_config, mConfigFile, false);
        } catch (IOException e) {
            throw new Utils.PsibotError("failed to prepare client files", e);
        }
    }

    private void consumeStream(InputStream inputStream) {
        try {
            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(inputStream));
            String line;
            while ((line = reader.readLine()) != null) {
                parseLine(line);
                // TODO: parse and use the Go client timestamp
                // Don't display the first 20 characters: the Go client log timestamp
                Log.addEntry(line.substring(20));
            }
            reader.close();
        } catch (IOException e) {
            // TODO: stop service if exiting due to error?
            Log.addEntry("Psiphon client consume error: " + e.getMessage());
        }
    }

    private synchronized void parseLine(String line) {
        // TODO: this is based on temporary log line formats
        final String socksProxy = "SOCKS-PROXY local SOCKS proxy running at address 127.0.0.1:";
        final String httpProxy = "HTTP-PROXY local HTTP proxy running at address 127.0.0.1:";
        final String homePage = "HOMEPAGE ";
        final String tunnelStarted = "TUNNEL tunnel started";
        int index;
        if (-1 != (index = line.indexOf(socksProxy))) {
            mLocalSocksProxyPort = Integer.parseInt(line.substring(index + socksProxy.length()));
        } else if (-1 != (index = line.indexOf(httpProxy))) {
            mLocalHttpProxyPort = Integer.parseInt(line.substring(index + httpProxy.length()));
        } else if (-1 != (index = line.indexOf(homePage))) {
            mHomePages.add(line.substring(index + homePage.length()));
        } else if (line.contains(tunnelStarted)) {
            mTunnelStartedSignal.countDown();
        }
    }
}
