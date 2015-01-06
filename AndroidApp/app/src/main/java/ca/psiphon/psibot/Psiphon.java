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
import android.content.SharedPreferences;
import android.net.VpnService;
import android.preference.PreferenceManager;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

import go.psi.Psi;

public class Psiphon extends Psi.PsiphonProvider.Stub {

    private final VpnService mVpnService;
    private final CountDownLatch mTunnelStartedSignal;
    private int mLocalSocksProxyPort;
    private int mLocalHttpProxyPort;
    private Set<String> mHomePages;

    public Psiphon(VpnService vpnService, CountDownLatch tunnelStartedSignal) {
        mVpnService = vpnService;
        mTunnelStartedSignal = tunnelStartedSignal;
    }

    // PsiphonProvider.Notice
    @Override
    public void Notice(String message) {
        message = message.trim();

        android.util.Log.d("PSIPHON", message);
        parseMessage(message);
        Log.addEntry(message);
    }

    // PsiphonProvider.BindToDevice
    @Override
    public void BindToDevice(long fileDescriptor) {
        // TODO: return result; currently no return value due to
        // Android Library limitation.
        mVpnService.protect((int)fileDescriptor);
    }

    public void start() throws Utils.PsibotError {
        Psi.Stop();

        mLocalSocksProxyPort = 0;
        mLocalHttpProxyPort = 0;
        mHomePages = new HashSet<String>();

        try {
            Psi.Start(loadConfig(mVpnService), this);
        } catch (Exception e) {
            throw new Utils.PsibotError("failed to start Psiphon", e);
        }

        Log.addEntry("Psiphon started");
    }

    public void stop() {
        Psi.Stop();
        Log.addEntry("Psiphon stopped");
    }

    public synchronized int getLocalSocksProxyPort() {
        return mLocalSocksProxyPort;
    }

    public synchronized int getLocalHttpProxyPort() {
        return mLocalHttpProxyPort;
    }

    public synchronized Set<String> getHomePages() {
        return mHomePages != null ? new HashSet<String>(mHomePages) : new HashSet<String>();
    }

    private String loadConfig(Context context)
            throws IOException, JSONException, Utils.PsibotError {

        // If we can obtain a DNS resolver for the active network,
        // prefer that for DNS resolution in BindToDevice mode.
        String dnsResolver = null;
        try {
            dnsResolver = Utils.getFirstActiveNetworkDnsResolver(context);
        } catch (Utils.PsibotError e) {
            Log.addEntry("failed to get active network DNS resolver: " + e.getMessage());
            // Proceed with default value in config file
        }

        // Load settings from the raw resource JSON config file and
        // update as necessary. Then write JSON to disk for the Go client.
        String configFileContents = Utils.readInputStreamToString(
                context.getResources().openRawResource(R.raw.psiphon_config));
        JSONObject json = new JSONObject(configFileContents);

        if (dnsResolver != null) {
            json.put("BindToDeviceDnsServer", dnsResolver);
        }

        // On Android, these directories must be set to the app private storage area.
        // The Psiphon library won't be able to use its current working directory
        // and the standard temporary directories do not exist.
        json.put("DataStoreDirectory", mVpnService.getFilesDir());
        json.put("DataStoreTempDirectory", mVpnService.getCacheDir());

        // User-specified settings.
        // Note: currently, validation is not comprehensive, and related errors are
        // not directly parsed.
        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);
        json.put("EgressRegion",
                preferences.getString(
                        context.getString(R.string.preferenceEgressRegion),
                        context.getString(R.string.preferenceEgressRegionDefaultValue)));
        json.put("TunnelProtocol",
                preferences.getString(
                        context.getString(R.string.preferenceTunnelProtocol),
                        context.getString(R.string.preferenceTunnelProtocolDefaultValue)));
        json.put("UpstreamHttpProxyAddress",
                preferences.getString(
                        context.getString(R.string.preferenceUpstreamHttpProxyAddress),
                        context.getString(R.string.preferenceUpstreamHttpProxyAddressDefaultValue)));
        json.put("LocalHttpProxyPort",
                Integer.parseInt(
                        preferences.getString(
                                context.getString(R.string.preferenceLocalHttpProxyPort),
                                context.getString(R.string.preferenceLocalHttpProxyPortDefaultValue))));
        json.put("LocalSocksProxyPort",
                Integer.parseInt(
                        preferences.getString(
                                context.getString(R.string.preferenceLocalSocksProxyPort),
                                context.getString(R.string.preferenceLocalSocksProxyPortDefaultValue))));
        json.put("ConnectionWorkerPoolSize",
                Integer.parseInt(
                        preferences.getString(
                                context.getString(R.string.preferenceConnectionWorkerPoolSize),
                                context.getString(R.string.preferenceConnectionWorkerPoolSizeDefaultValue))));
        json.put("TunnelPoolSize",
                Integer.parseInt(
                        preferences.getString(
                                context.getString(R.string.preferenceTunnelPoolSize),
                                context.getString(R.string.preferenceTunnelPoolSizeDefaultValue))));
        json.put("PortForwardFailureThreshold",
                Integer.parseInt(
                        preferences.getString(
                                context.getString(R.string.preferencePortForwardFailureThreshold),
                                context.getString(R.string.preferencePortForwardFailureThresholdDefaultValue))));

        return json.toString();
    }

    private synchronized void parseMessage(String message) {
        // TODO: this is based on tentative log line formats
        final String socksProxy = "SOCKS-PROXY-PORT ";
        final String httpProxy = "HTTP-PROXY-PORT ";
        final String homePage = "HOMEPAGE ";
        final String tunnelStarted = "TUNNELS 1";
        int index;
        if (-1 != (index = message.indexOf(socksProxy))) {
            mLocalSocksProxyPort = Integer.parseInt(message.substring(index + socksProxy.length()));
        } else if (-1 != (index = message.indexOf(httpProxy))) {
            mLocalHttpProxyPort = Integer.parseInt(message.substring(index + httpProxy.length()));
        } else if (-1 != (index = message.indexOf(homePage))) {
            mHomePages.add(message.substring(index + homePage.length()));
        } else if (message.contains(tunnelStarted)) {
            mTunnelStartedSignal.countDown();
        }
    }
}
