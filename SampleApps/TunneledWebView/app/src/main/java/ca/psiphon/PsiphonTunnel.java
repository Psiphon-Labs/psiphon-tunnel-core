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

package ca.psiphon;

import android.annotation.TargetApi;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.telephony.TelephonyManager;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

import go.psi.Psi;

public class PsiphonTunnel extends Psi.PsiphonProvider.Stub {

    public interface TunneledApp {
        Context getContext();
        String getPsiphonConfig();
        void onDiagnosticMessage(String message);
        void onAvailableEgressRegions(List<String> regions);
        void onSocksProxyPortInUse(int port);
        void onHttpProxyPortInUse(int port);
        void onListeningSocksProxyPort(int port);
        void onListeningHttpProxyPort(int port);
        void onUpstreamProxyError(String message);
        void onConnecting();
        void onConnected();
        void onHomepage(String url);
        void onClientRegion(String region);
        void onClientUpgradeDownloaded(String filename);
        void onSplitTunnelRegion(String region);
        void onUntunneledAddress(String address);
        void onBytesTransferred(long sent, long received);
        void onStartedWaitingForNetworkConnectivity();
    }

    private final TunneledApp mTunneledApp;
    private AtomicBoolean mIsWaitingForNetworkConnectivity;

    // Only one PsiphonVpn instance may exist at a time, as the underlying
    // go.psi.Psi contains global state.
    private static PsiphonTunnel mPsiphonTunnel;

    public static synchronized PsiphonTunnel newPsiphonTunnel(TunneledApp tunneledApp) {
        if (mPsiphonTunnel != null) {
            mPsiphonTunnel.stop();
        }
        // Load the native go code embedded in psi.aar
        System.loadLibrary("gojni");
        mPsiphonTunnel = new PsiphonTunnel(tunneledApp);
        return mPsiphonTunnel;
    }

    private PsiphonTunnel(TunneledApp tunneledApp) {
        mTunneledApp = tunneledApp;
        mIsWaitingForNetworkConnectivity = new AtomicBoolean(false);
    }

    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    //----------------------------------------------------------------------------------------------
    // Public API
    //----------------------------------------------------------------------------------------------

    public synchronized boolean start(String embeddedServerEntries) {
        return startPsiphon(embeddedServerEntries);
    }

    public synchronized void stop() {
        stopPsiphon();
    }

    //----------------------------------------------------------------------------------------------
    // PsiphonProvider (Core support) interface implementation
    //----------------------------------------------------------------------------------------------

    @Override
    public void Notice(String noticeJSON) {
        handlePsiphonNotice(noticeJSON);
    }

    @TargetApi(Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    @Override
    public void BindToDevice(long fileDescriptor) throws Exception {
        // This PsiphonProvider function is only called in TunnelWholeDevice mode
        throw new Exception("BindToDevice not supported");
    }

    @Override
    public long HasNetworkConnectivity() {
        boolean hasConnectivity = hasNetworkConnectivity(mTunneledApp.getContext());
        boolean wasWaitingForNetworkConnectivity = mIsWaitingForNetworkConnectivity.getAndSet(!hasConnectivity);
        if (!hasConnectivity && !wasWaitingForNetworkConnectivity) {
            // HasNetworkConnectivity may be called many times, but only call
            // onStartedWaitingForNetworkConnectivity once per loss of connectivity,
            // so the HostService may log a single message.
            mTunneledApp.onStartedWaitingForNetworkConnectivity();
        }
        // TODO: change to bool return value once gobind supports that type
        return hasConnectivity ? 1 : 0;
    }

    private static boolean hasNetworkConnectivity(Context context) {
        ConnectivityManager connectivityManager =
                (ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connectivityManager.getActiveNetworkInfo();
        return networkInfo != null && networkInfo.isConnected();
    }

    @Override
    public String GetPrimaryDnsServer() {
        // This PsiphonProvider function is only called in TunnelWholeDevice mode
        return "";
    }

    @Override
    public String GetSecondaryDnsServer() {
        // This PsiphonProvider function is only called in TunnelWholeDevice mode
        return "";
    }

    //----------------------------------------------------------------------------------------------
    // Psiphon Tunnel Core
    //----------------------------------------------------------------------------------------------

    private boolean startPsiphon(String embeddedServerEntries) {
        stopPsiphon();
        mTunneledApp.onDiagnosticMessage("starting Psiphon library");
        try {
            Psi.Start(
                    loadPsiphonConfig(mTunneledApp.getContext()),
                    embeddedServerEntries,
                    this,
                    false);
        } catch (java.lang.Exception e) {
            mTunneledApp.onDiagnosticMessage("failed to start Psiphon library: " + e.getMessage());
            return false;
        }
        mTunneledApp.onDiagnosticMessage("Psiphon library started");
        return true;
    }

    private void stopPsiphon() {
        mTunneledApp.onDiagnosticMessage("stopping Psiphon library");
        Psi.Stop();
        mTunneledApp.onDiagnosticMessage("Psiphon library stopped");
    }

    private String loadPsiphonConfig(Context context)
            throws IOException, JSONException {

        // Load settings from the raw resource JSON config file and
        // update as necessary. Then write JSON to disk for the Go client.
        JSONObject json = new JSONObject(mTunneledApp.getPsiphonConfig());

        // On Android, these directories must be set to the app private storage area.
        // The Psiphon library won't be able to use its current working directory
        // and the standard temporary directories do not exist.
        json.put("DataStoreDirectory", context.getFilesDir());
        json.put("DataStoreTempDirectory", context.getCacheDir());

        // Note: onConnecting/onConnected logic assumes 1 tunnel connection
        json.put("TunnelPoolSize", 1);

        // Continue to run indefinitely until connected
        json.put("EstablishTunnelTimeoutSeconds", 0);

        // This parameter is for stats reporting
        json.put("TunnelWholeDevice", 0);

        json.put("EmitBytesTransferred", true);

        json.put("UseIndistinguishableTLS", true);

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
            json.put("UseTrustedCACertificatesForStockTLS", true);
        }

        try {
            // Also enable indistinguishable TLS for HTTPS requests that
            // require system CAs.
            json.put(
                    "TrustedCACertificatesFilename",
                    setupTrustedCertificates(mTunneledApp.getContext()));
        } catch (Exception e) {
            mTunneledApp.onDiagnosticMessage(e.getMessage());
        }

        json.put("DeviceRegion", getDeviceRegion(mTunneledApp.getContext()));

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
                if (count > 0) {
                    mTunneledApp.onConnected();
                } else {
                    mTunneledApp.onConnecting();
                }

            } else if (noticeType.equals("AvailableEgressRegions")) {
                JSONArray egressRegions = notice.getJSONObject("data").getJSONArray("regions");
                ArrayList<String> regions = new ArrayList<String>();
                for (int i=0; i<egressRegions.length(); i++) {
                    regions.add(egressRegions.getString(i));
                }
                mTunneledApp.onAvailableEgressRegions(regions);

            } else if (noticeType.equals("SocksProxyPortInUse")) {
                mTunneledApp.onSocksProxyPortInUse(notice.getJSONObject("data").getInt("port"));

            } else if (noticeType.equals("HttpProxyPortInUse")) {
                mTunneledApp.onHttpProxyPortInUse(notice.getJSONObject("data").getInt("port"));

            } else if (noticeType.equals("ListeningSocksProxyPort")) {
                int port = notice.getJSONObject("data").getInt("port");
                mTunneledApp.onListeningSocksProxyPort(port);

            } else if (noticeType.equals("ListeningHttpProxyPort")) {
                int port = notice.getJSONObject("data").getInt("port");
                mTunneledApp.onListeningHttpProxyPort(port);

            } else if (noticeType.equals("UpstreamProxyError")) {
                mTunneledApp.onUpstreamProxyError(notice.getJSONObject("data").getString("message"));

            } else if (noticeType.equals("ClientUpgradeDownloaded")) {
                mTunneledApp.onClientUpgradeDownloaded(notice.getJSONObject("data").getString("filename"));

            } else if (noticeType.equals("Homepage")) {
                mTunneledApp.onHomepage(notice.getJSONObject("data").getString("url"));

            } else if (noticeType.equals("ClientRegion")) {
                mTunneledApp.onClientRegion(notice.getJSONObject("data").getString("region"));

            } else if (noticeType.equals("SplitTunnelRegion")) {
                mTunneledApp.onSplitTunnelRegion(notice.getJSONObject("data").getString("region"));

            } else if (noticeType.equals("UntunneledAddress")) {
                mTunneledApp.onUntunneledAddress(notice.getJSONObject("data").getString("address"));

            } else if (noticeType.equals("BytesTransferred")) {
                diagnostic = false;
                JSONObject data = notice.getJSONObject("data");
                mTunneledApp.onBytesTransferred(data.getLong("sent"), data.getLong("received"));
            }

            if (diagnostic) {
                String diagnosticMessage = noticeType + ": " + notice.getJSONObject("data").toString();
                mTunneledApp.onDiagnosticMessage(diagnosticMessage);
            }

        } catch (JSONException e) {
            // Ignore notice
        }
    }

    private String setupTrustedCertificates(Context context) throws Exception {

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

                mTunneledApp.onDiagnosticMessage("prepared PsiphonCAStore");

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
            region = telephonyManager.getSimCountryIso();
            if (region.length() == 0 && telephonyManager.getPhoneType() != TelephonyManager.PHONE_TYPE_CDMA) {
                region = telephonyManager.getNetworkCountryIso();
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
}
