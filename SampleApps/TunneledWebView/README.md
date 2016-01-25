TunneledWebView README
================================================================================

Overview
--------------------------------------------------------------------------------

TunneledWebView is a sample app that demonstrates embedding the Psiphon Library in
an Android app. TunneledWebView proxies a WebView through the Psiphon tunnel.

Integration
--------------------------------------------------------------------------------

Uses the [Psiphon Android Library](../../AndroidLibrary/README.md).

Integration is illustrated in the main activity source file in the sample app. Here are the key parts.

```Java

/*
 * Copyright (c) 2016, Psiphon Inc.
 * All rights reserved.
 */
 
package ca.psiphon.tunneledwebview;

// ...

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
        implements PsiphonTunnel.TunneledApp {

// ...

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        // ...

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

        if (!mPsiphonTunnel.start("")) {
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

    // ...

    //----------------------------------------------------------------------------------------------
    // PsiphonTunnel.TunneledApp implementation
    //
    // NOTE: these are callbacks from the Psiphon Library
    //----------------------------------------------------------------------------------------------

    // ...

    @Override
    public void onListeningSocksProxyPort(int port) {
        logMessage("local SOCKS proxy listening on port: " + Integer.toString(port));
    }

    // ...

    @Override
    public void onConnected() {
        logMessage("connected");
        loadWebView();
    }

    // ...

}

```
