/*
 * Copyright (c) 2013, Psiphon Inc.
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

import android.os.Handler;

import java.util.ArrayList;
import java.util.Date;

public class Log {

    public static class Entry {
        public final Date mTimestamp;
        public final String mMessage;

        public Entry(String message) {
            mTimestamp = new Date();
            mMessage = message;
        }
    }

    public interface Observer {
        void onUpdatedRecentEntries();
    }

    private static final int MAX_ENTRIES = 500;

    private static ArrayList<Entry> mEntries;
    private static ArrayList<Observer> mObservers;
    private static Handler mHandler;

    public synchronized static void initialize() {
        mEntries = new ArrayList<Entry>();
        mObservers = new ArrayList<Observer>();
        mHandler = new Handler();
    }

    public synchronized static void addEntry(String message) {
        if (message == null) {
            message = "(null)";
        }
        final Entry entry = new Entry(message);

        // Update the in-memory entry list on the UI thread (also
        // notifies any ListView adapters subscribed to that list)
        mHandler.post(
                new Runnable() {
                    @Override
                    public void run() {
                        mEntries.add(entry);
                        while (mEntries.size() > MAX_ENTRIES) {
                            mEntries.remove(0);
                        }
                        for (Observer observer : mObservers) {
                            observer.onUpdatedRecentEntries();
                        }
                    }
                });
    }

    public synchronized static int getEntryCount() {
        return mEntries.size();
    }

    public synchronized static Entry getEntry(int index) {
        return mEntries.get(index);
    }

    public synchronized static void registerObserver(Observer observer) {
        if (!mObservers.contains(observer)) {
            mObservers.add(observer);
        }
    }

    public synchronized static void unregisterObserver(Observer observer) {
        mObservers.remove(observer);
    }
}
