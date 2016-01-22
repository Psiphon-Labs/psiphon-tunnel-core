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

package ca.psiphon.psibot;

import android.app.Notification;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.preference.PreferenceManager;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ca.psiphon.PsiphonTunnel;

public class Service extends VpnService
        implements PsiphonTunnel.HostService, SharedPreferences.OnSharedPreferenceChangeListener {

    private PsiphonTunnel mPsiphonTunnel;

    @Override
    public void onCreate() {
        mPsiphonTunnel = PsiphonTunnel.newPsiphonTunnel(this);
        startForeground(R.string.foregroundServiceNotificationId, makeForegroundNotification());
        try {
            if (!mPsiphonTunnel.startRouting()) {
                throw new PsiphonTunnel.Exception("VPN not prepared");
            }
            mPsiphonTunnel.startTunneling("");
        } catch (PsiphonTunnel.Exception e) {
            Log.addEntry("failed to start Psiphon VPN: " + e.getMessage());
            mPsiphonTunnel.stop();
            stopSelf();
        }
        PreferenceManager.getDefaultSharedPreferences(this).
                registerOnSharedPreferenceChangeListener(this);
    }

    @Override
    public void onDestroy() {
        PreferenceManager.getDefaultSharedPreferences(this).
                unregisterOnSharedPreferenceChangeListener(this);
        mPsiphonTunnel.stop();
        stopForeground(true);
    }

    @Override
    public synchronized void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
        try {
            mPsiphonTunnel.restartPsiphon();
        } catch (PsiphonTunnel.Exception e) {
            Log.addEntry("failed to restart Psiphon: " + e.getMessage());
            mPsiphonTunnel.stop();
            stopSelf();
        }
    }

    @Override
    public String getAppName() {
        return getString(R.string.app_name);
    }

    @Override
    public Context getContext() {
        return this;
    }

    @Override
    public VpnService getVpnService() {
        return this;
    }

    @Override
    public VpnService.Builder newVpnServiceBuilder() {
        return new VpnService.Builder();
    }

    @Override
    public String getPsiphonConfig() {
        try {
            JSONObject config = new JSONObject(
                    readInputStreamToString(
                        getResources().openRawResource(R.raw.psiphon_config)));

            // Insert user-specified settings.
            // Note: currently, validation is not comprehensive, and related errors are
            // not directly parsed.
            SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);
            config.put("EgressRegion",
                    preferences.getString(
                            getString(R.string.preferenceEgressRegion),
                            getString(R.string.preferenceEgressRegionDefaultValue)));
            config.put("TunnelProtocol",
                    preferences.getString(
                            getString(R.string.preferenceTunnelProtocol),
                            getString(R.string.preferenceTunnelProtocolDefaultValue)));
            config.put("UpstreamProxyUrl",
                    preferences.getString(
                            getString(R.string.preferenceUpstreamProxyUrl),
                            getString(R.string.preferenceUpstreamProxyUrlDefaultValue)));
            config.put("LocalHttpProxyPort",
                    Integer.parseInt(
                            preferences.getString(
                                    getString(R.string.preferenceLocalHttpProxyPort),
                                    getString(R.string.preferenceLocalHttpProxyPortDefaultValue))));
            config.put("LocalSocksProxyPort",
                    Integer.parseInt(
                            preferences.getString(
                                    getString(R.string.preferenceLocalSocksProxyPort),
                                    getString(R.string.preferenceLocalSocksProxyPortDefaultValue))));
            config.put("ConnectionWorkerPoolSize",
                    Integer.parseInt(
                            preferences.getString(
                                    getString(R.string.preferenceConnectionWorkerPoolSize),
                                    getString(R.string.preferenceConnectionWorkerPoolSizeDefaultValue))));
            config.put("TunnelPoolSize",
                    Integer.parseInt(
                            preferences.getString(
                                    getString(R.string.preferenceTunnelPoolSize),
                                    getString(R.string.preferenceTunnelPoolSizeDefaultValue))));
            config.put("PortForwardFailureThreshold",
                    Integer.parseInt(
                            preferences.getString(
                                    getString(R.string.preferencePortForwardFailureThreshold),
                                    getString(R.string.preferencePortForwardFailureThresholdDefaultValue))));

            return config.toString();

        } catch (IOException e) {
            Log.addEntry("error setting config parameters: " + e.getMessage());
        } catch (JSONException e) {
            Log.addEntry("error setting config parameters: " + e.getMessage());
        }
        return "";
    }

    @Override
    public void onDiagnosticMessage(String message) {
        android.util.Log.i(getString(R.string.app_name), message);
        Log.addEntry(message);
    }

    @Override
    public void onAvailableEgressRegions(List<String> regions) {
        // TODO: show only available regions in SettingActivity
    }

    @Override
    public void onSocksProxyPortInUse(int port) {
        Log.addEntry("local SOCKS proxy port in use: " + Integer.toString(port));
    }

    @Override
    public void onHttpProxyPortInUse(int port) {
        Log.addEntry("local HTTP proxy port in use: " + Integer.toString(port));
    }

    @Override
    public void onListeningSocksProxyPort(int port) {
        Log.addEntry("local SOCKS proxy listening on port: " + Integer.toString(port));
    }

    @Override
    public void onListeningHttpProxyPort(int port) {
        Log.addEntry("local HTTP proxy listening on port: " + Integer.toString(port));
    }

    @Override
    public void onUpstreamProxyError(String message) {
        Log.addEntry("upstream proxy error: " + message);
    }

    @Override
    public void onConnecting() {
        Log.addEntry("connecting...");
    }

    @Override
    public void onConnected() {
        Log.addEntry("connected");
    }

    @Override
    public void onHomepage(String url) {
        Log.addEntry("home page: " + url);
    }

    @Override
    public void onClientUpgradeDownloaded(String filename) {
        Log.addEntry("client upgrade downloaded");
    }

    @Override
    public void onSplitTunnelRegion(String region) {
        Log.addEntry("split tunnel region: " + region);
    }

    @Override
    public void onUntunneledAddress(String address) {
        Log.addEntry("untunneled address: " + address);
    }

    @Override
    public void onBytesTransferred(long sent, long received) {
    }

    @Override
    public void onStartedWaitingForNetworkConnectivity() {
        Log.addEntry("waiting for network connectivity...");
    }

    @Override
    public void onClientRegion(String region) {
        Log.addEntry("client region: " + region);
    }

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
