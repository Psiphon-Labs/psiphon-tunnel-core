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

package ca.psiphon.tunneledwebview;

import android.content.Context;
import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.webkit.WebView;
import android.widget.ArrayAdapter;
import android.widget.ListView;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import ca.psiphon.PsiphonTunnel;

//----------------------------------------------------------------------------------------------
// TunneledWebView
//
// This sample app demonstrates tunneling a WebView through the
// Psiphon Library. This app's main activity shows a log of
// events and a WebView that is loaded once Psiphon is connected.
//
// The flow is as follows:
//
// - The Psiphon tunnel is started in onResume(). PsiphonTunnel.start()
//   is an asynchronous call that returns immediately.
//
// - Once Psiphon has selected a local HTTP proxy listening port, the
//   onListeningHttpProxyPort() callback is called. This app records the
//   port to use for tunneling traffic.
//
// - Once Psiphon has established a tunnel, the onConnected() callback
//   is called. This app now loads the WebView, after setting its proxy
//   to point to Psiphon's local HTTP proxy.
//
// To adapt this sample into your own app:
//
// - Embed a Psiphon config file in app/src/main/res/raw/psiphon_config.
//
// - Add the Psiphon Library AAR module as a dependency (see this app's
//   project settings; to build this sample project, you need to drop
//   psi-0.0.10.aar into app/libs).
//
// - Use app/src/main/java/ca/psiphon/PsiphonTunnel.java, which provides
//   a higher-level wrapper around the Psiphon Library module. This file
//   shows how to use PsiphonTunnel and PsiphonTunnel.TunneledApp.
//
//----------------------------------------------------------------------------------------------

public class MainActivity extends ActionBarActivity
        implements PsiphonTunnel.HostService {

    private ListView mListView;
    private WebView mWebView;

    private ArrayAdapter<String> mLogMessages;
    private AtomicInteger mLocalHttpProxyPort;

    private PsiphonTunnel mPsiphonTunnel;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mListView = (ListView)findViewById(R.id.listView);
        mWebView = (WebView)findViewById(R.id.webView);

        mLogMessages = new ArrayAdapter<String>(
                this, R.layout.log_message, R.id.logMessageTextView);

        mListView.setAdapter(mLogMessages);

        mLocalHttpProxyPort = new AtomicInteger(0);

        mPsiphonTunnel = PsiphonTunnel.newPsiphonTunnel(this);
    }

    @Override
    protected void onResume() {
        super.onResume();

        // NOTE: for demonstration purposes, this sample app
        // restarts Psiphon in onPause/onResume. Since it may take some
        // time to connect, it's generally recommended to keep
        // Psiphon running, so start/stop in onCreate/onDestroy or
        // even consider running a background Service.


        try {
            mPsiphonTunnel.startTunneling("");
        } catch (PsiphonTunnel.Exception e) {
            logMessage("failed to start Psiphon");
        }
    }

    @Override
    protected void onPause() {
        super.onPause();

        // NOTE: stop() can block for a few seconds, so it's generally
        // recommended to run PsiphonTunnel.start()/stop() in a background
        // thread and signal the thread appropriately.

        mPsiphonTunnel.stop();
    }

    private void setHttpProxyPort(int port) {

        // NOTE: here we record the Psiphon proxy port for subsequent
        // use in tunneling app traffic. In this sample app, we will
        // use WebViewProxySettings.setLocalProxy to tunnel a WebView
        // through Psiphon. By default, the local proxy port is selected
        // dynamically, so it's important to record and use the correct
        // port number.

        mLocalHttpProxyPort.set(port);
    }

    private void loadWebView() {

        // NOTE: functions called via PsiphonTunnel.TunneledApp may be
        // called on background threads. It's important to ensure that
        // these threads are not blocked and that UI functions are not
        // called directly from these threads. Here we use runOnUiThread
        // to handle this.

        runOnUiThread(new Runnable() {
            public void run() {
                WebViewProxySettings.setLocalProxy(
                        MainActivity.this, mLocalHttpProxyPort.get());
                mWebView.loadUrl("https://ipinfo.io/");
            }
        });
    }

    private void logMessage(final String message) {
        runOnUiThread(new Runnable() {
            public void run() {
                mLogMessages.add(message);
                mListView.setSelection(mLogMessages.getCount() - 1);
            }
        });
    }

    //----------------------------------------------------------------------------------------------
    // PsiphonTunnel.TunneledApp implementation
    //
    // NOTE: these are callbacks from the Psiphon Library
    //----------------------------------------------------------------------------------------------

    @Override
    public String getAppName() {
        return "TunneledWebView Sample";
    }

    @Override
    public Context getContext() {
        return this;
    }

    @Override
    public Object getVpnService() {
        return null;
    }

    @Override
    public Object newVpnServiceBuilder() {
        return null;
    }

    @Override
    public String getPsiphonConfig() {
        try {
            JSONObject config = new JSONObject(
                    readInputStreamToString(
                            getResources().openRawResource(R.raw.psiphon_config)));

            return config.toString();

        } catch (IOException e) {
            logMessage("error loading Psiphon config: " + e.getMessage());
        } catch (JSONException e) {
            logMessage("error loading Psiphon config: " + e.getMessage());
        }
        return "";
    }

    @Override
    public void onDiagnosticMessage(String message) {
        android.util.Log.i(getString(R.string.app_name), message);
        logMessage(message);
    }

    @Override
    public void onAvailableEgressRegions(List<String> regions) {
        for (String region : regions) {
            logMessage("available egress region: " + region);
        }
    }

    @Override
    public void onSocksProxyPortInUse(int port) {
        logMessage("local SOCKS proxy port in use: " + Integer.toString(port));
    }

    @Override
    public void onHttpProxyPortInUse(int port) {
        logMessage("local HTTP proxy port in use: " + Integer.toString(port));
    }

    @Override
    public void onListeningSocksProxyPort(int port) {
        logMessage("local SOCKS proxy listening on port: " + Integer.toString(port));
    }

    @Override
    public void onListeningHttpProxyPort(int port) {
        logMessage("local HTTP proxy listening on port: " + Integer.toString(port));
        setHttpProxyPort(port);
    }

    @Override
    public void onUpstreamProxyError(String message) {
        logMessage("upstream proxy error: " + message);
    }

    @Override
    public void onConnecting() {
        logMessage("connecting...");
    }

    @Override
    public void onConnected() {
        logMessage("connected");
        loadWebView();
    }

    @Override
    public void onHomepage(String url) {
        logMessage("home page: " + url);
    }

    @Override
    public void onClientUpgradeDownloaded(String filename) {
        logMessage("client upgrade downloaded");
    }

    @Override
    public void onClientIsLatestVersion() {

    }

    @Override
    public void onSplitTunnelRegion(String region) {
        logMessage("split tunnel region: " + region);
    }

    @Override
    public void onUntunneledAddress(String address) {
        logMessage("untunneled address: " + address);
    }

    @Override
    public void onBytesTransferred(long sent, long received) {
        logMessage("bytes sent: " + Long.toString(sent));
        logMessage("bytes received: " + Long.toString(received));
    }

    @Override
    public void onStartedWaitingForNetworkConnectivity() {
        logMessage("waiting for network connectivity...");
    }

    @Override
    public void onClientVerificationRequired(String s, int i, boolean b) {

    }

    @Override
    public void onExiting() {

    }

    @Override
    public void onClientRegion(String region) {
        logMessage("client region: " + region);
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
}
