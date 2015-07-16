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
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.preference.PreferenceManager;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.InputStream;

import ca.psiphon.PsiphonVpn;

public class Service extends VpnService
        implements PsiphonVpn.HostService, SharedPreferences.OnSharedPreferenceChangeListener {

    private PsiphonVpn mPsiphonVpn;

    @Override
    public void onCreate() {
        mPsiphonVpn = PsiphonVpn.newPsiphonVpn(this);
        startForeground(R.string.foregroundServiceNotificationId, makeForegroundNotification());
        try {
            if (!mPsiphonVpn.startRouting()) {
                throw new PsiphonVpn.Exception("VPN not prepared");
            }
            mPsiphonVpn.startTunneling();
        } catch (PsiphonVpn.Exception e) {
            Log.addEntry("failed to start Psiphon VPN: " + e.getMessage());
            mPsiphonVpn.stop();
            stopSelf();
        }
        PreferenceManager.getDefaultSharedPreferences(this).
                registerOnSharedPreferenceChangeListener(this);
    }

    @Override
    public void onDestroy() {
        PreferenceManager.getDefaultSharedPreferences(this).
                unregisterOnSharedPreferenceChangeListener(this);
        mPsiphonVpn.stop();
        stopForeground(true);
    }

    @Override
    public synchronized void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
        try {
            mPsiphonVpn.restartPsiphon();
        } catch (PsiphonVpn.Exception e) {
            Log.addEntry("failed to restart Psiphon: " + e.getMessage());
            mPsiphonVpn.stop();
            stopSelf();
        }
    }

    @Override
    public String getAppName() {
        return getString(R.string.app_name);
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
    public InputStream getPsiphonConfigResource() {
        return getResources().openRawResource(R.raw.psiphon_config);
    }

    @Override
    public void customizeConfigParameters(JSONObject config) {
        // User-specified settings.
        // Note: currently, validation is not comprehensive, and related errors are
        // not directly parsed.
        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);
        try {
            config.put("EgressRegion",
                    preferences.getString(
                            getString(R.string.preferenceEgressRegion),
                            getString(R.string.preferenceEgressRegionDefaultValue)));
            config.put("TunnelProtocol",
                    preferences.getString(
                            getString(R.string.preferenceTunnelProtocol),
                            getString(R.string.preferenceTunnelProtocolDefaultValue)));
            config.put("UpstreamHttpProxyAddress",
                    preferences.getString(
                            getString(R.string.preferenceUpstreamHttpProxyAddress),
                            getString(R.string.preferenceUpstreamHttpProxyAddressDefaultValue)));
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
        } catch (JSONException e) {
            Log.addEntry("error setting config parameters: " + e.getMessage());
        }
    }

    @Override
    public void logWarning(String message) {
        android.util.Log.w(getString(R.string.app_name), message);
        Log.addEntry(message);
    }

    @Override
    public void logInfo(String message) {
        android.util.Log.i(getString(R.string.app_name), message);
        Log.addEntry(message);
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
