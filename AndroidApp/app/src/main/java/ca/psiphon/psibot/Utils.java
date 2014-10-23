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
import android.net.ConnectivityManager;
import android.net.NetworkInfo;

import org.apache.http.conn.util.InetAddressUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.zip.ZipInputStream;


public class Utils {

    public static class PsibotError extends Exception {
        private static final long serialVersionUID = 1L;

        public PsibotError() {
            super();
        }

        public PsibotError(String message) {
            super(message);
        }

        public PsibotError(String message, Throwable cause) {
            super(message, cause);
        }

        public PsibotError(Throwable cause) {
            super(cause);
        }
    }

    public static void copyStream(
            InputStream inputStream, OutputStream outputStream) throws IOException {
        try {
            byte[] buffer = new byte[16384];
            int length;
            while ((length = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0 , length);
            }
        } finally {
            inputStream.close();
            outputStream.close();
        }
    }

    public static void writeRawResourceFile(
            Context context, int resId, File file, boolean setExecutable) throws IOException {
        file.delete();
        InputStream zippedAsset = context.getResources().openRawResource(resId);
        ZipInputStream zipStream = new ZipInputStream(zippedAsset);
        zipStream.getNextEntry();
        Utils.copyStream(zipStream, new FileOutputStream(file));
        if (setExecutable && !file.setExecutable(true)) {
            throw new IOException("failed to set file as executable");
        }
    }

    public static String getNetworkTypeName(Context context) {
        ConnectivityManager connectivityManager =
                (ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connectivityManager.getActiveNetworkInfo();
        return networkInfo == null ? "" : networkInfo.getTypeName();
    }

    private static final String CANDIDATE_10_SLASH_8 = "10.0.0.1";
    private static final String SUBNET_10_SLASH_8 = "10.0.0.0";
    private static final int PREFIX_LENGTH_10_SLASH_8 = 8;
    private static final String ROUTER_10_SLASH_8 = "10.0.0.2";

    private static final String CANDIDATE_172_16_SLASH_12 = "172.16.0.1";
    private static final String SUBNET_172_16_SLASH_12 = "172.16.0.0";
    private static final int PREFIX_LENGTH_172_16_SLASH_12 = 12;
    private static final String ROUTER_172_16_SLASH_12 = "172.16.0.2";

    private static final String CANDIDATE_192_168_SLASH_16 = "192.168.0.1";        
    private static final String SUBNET_192_168_SLASH_16 = "192.168.0.0";
    private static final int PREFIX_LENGTH_192_168_SLASH_16 = 16;
    private static final String ROUTER_192_168_SLASH_16 = "192.168.0.2";
    
    private static final String CANDIDATE_169_254_1_SLASH_24 = "169.254.1.1";        
    private static final String SUBNET_169_254_1_SLASH_24 = "169.254.1.0";
    private static final int PREFIX_LENGTH_169_254_1_SLASH_24 = 24;
    private static final String ROUTER_169_254_1_SLASH_24 = "169.254.1.2";
    
    public static String selectPrivateAddress() {
        // Select one of 10.0.0.1, 172.16.0.1, or 192.168.0.1 depending on
        // which private address range isn't in use.

        ArrayList<String> candidates = new ArrayList<String>();
        candidates.add(CANDIDATE_10_SLASH_8);
        candidates.add(CANDIDATE_172_16_SLASH_12);
        candidates.add(CANDIDATE_192_168_SLASH_16);
        candidates.add(CANDIDATE_169_254_1_SLASH_24);
        
        List<NetworkInterface> netInterfaces;
        try {
            netInterfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
        } catch (SocketException e) {
            return null;
        }

        for (NetworkInterface netInterface : netInterfaces) {
            for (InetAddress inetAddress : Collections.list(netInterface.getInetAddresses())) {
                String ipAddress = inetAddress.getHostAddress();
                if (InetAddressUtils.isIPv4Address(ipAddress)) {
                    if (ipAddress.startsWith("10.")) {
                        candidates.remove(CANDIDATE_10_SLASH_8);
                    }
                    else if (
                        ipAddress.length() >= 6 &&
                        ipAddress.substring(0, 6).compareTo("172.16") >= 0 && 
                        ipAddress.substring(0, 6).compareTo("172.31") <= 0) {
                        candidates.remove(CANDIDATE_172_16_SLASH_12);
                    }
                    else if (ipAddress.startsWith("192.168")) {
                        candidates.remove(CANDIDATE_192_168_SLASH_16);
                    }
                }
            }
        }
        
        if (candidates.size() > 0) {
            return candidates.get(0);
        }
        
        return null;
    }
    
    public static String getPrivateAddressSubnet(String privateIpAddress) {
        if (0 == privateIpAddress.compareTo(CANDIDATE_10_SLASH_8)) {
            return SUBNET_10_SLASH_8;
        }
        else if (0 == privateIpAddress.compareTo(CANDIDATE_172_16_SLASH_12)) {
            return SUBNET_172_16_SLASH_12;
        }
        else if (0 == privateIpAddress.compareTo(CANDIDATE_192_168_SLASH_16)) {
            return SUBNET_192_168_SLASH_16;
        }
        else if (0 == privateIpAddress.compareTo(CANDIDATE_169_254_1_SLASH_24)) {
            return SUBNET_169_254_1_SLASH_24;
        }
        return null;
    }
    
    public static int getPrivateAddressPrefixLength(String privateIpAddress) {
        if (0 == privateIpAddress.compareTo(CANDIDATE_10_SLASH_8)) {
            return PREFIX_LENGTH_10_SLASH_8;
        }
        else if (0 == privateIpAddress.compareTo(CANDIDATE_172_16_SLASH_12)) {
            return PREFIX_LENGTH_172_16_SLASH_12;
        }
        else if (0 == privateIpAddress.compareTo(CANDIDATE_192_168_SLASH_16)) {
            return PREFIX_LENGTH_192_168_SLASH_16;
        }
        else if (0 == privateIpAddress.compareTo(CANDIDATE_169_254_1_SLASH_24)) {
            return PREFIX_LENGTH_169_254_1_SLASH_24;
        }
        return 0;
    }
    
    public static String getPrivateAddressRouter(String privateIpAddress) {
        if (0 == privateIpAddress.compareTo(CANDIDATE_10_SLASH_8)) {
            return ROUTER_10_SLASH_8;
        }
        else if (0 == privateIpAddress.compareTo(CANDIDATE_172_16_SLASH_12)) {
            return ROUTER_172_16_SLASH_12;
        }
        else if (0 == privateIpAddress.compareTo(CANDIDATE_192_168_SLASH_16)) {
            return ROUTER_192_168_SLASH_16;
        }
        else if (0 == privateIpAddress.compareTo(CANDIDATE_169_254_1_SLASH_24)) {
            return ROUTER_169_254_1_SLASH_24;
        }
        return null;
    }
}
