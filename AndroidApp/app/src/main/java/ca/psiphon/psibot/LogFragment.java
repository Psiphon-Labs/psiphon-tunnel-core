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

import android.app.ListFragment;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ListView;
import android.widget.TextView;

import java.text.DateFormat;

public class LogFragment extends ListFragment implements Log.Observer {

    private LogAdapter mLogAdapter;

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        mLogAdapter = new LogAdapter(getActivity());
        setListAdapter(mLogAdapter);
    }

    @Override
    public void onResume() {
        super.onResume();
        Log.registerObserver(this);
        getListView().setSelection(mLogAdapter.getCount() - 1);
        getListView().setTranscriptMode(ListView.TRANSCRIPT_MODE_ALWAYS_SCROLL);
    }

    @Override
    public void onPause() {
        super.onPause();
        Log.unregisterObserver(this);
    }

    @Override
    public void onUpdatedRecentEntries() {
        mLogAdapter.notifyDataSetChanged();
        getListView().setSelection(mLogAdapter.getCount() - 1);
    }

    private static class LogAdapter extends BaseAdapter {
        private final Context mContext;
        private final DateFormat mDateFormat;

        public LogAdapter(Context context) {
            mContext = context;
            mDateFormat = DateFormat.getDateTimeInstance();
        }

        @Override
        public View getView(int position, View view, ViewGroup parent) {
            if (view == null) {
                LayoutInflater inflater = (LayoutInflater)mContext.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
                view = inflater.inflate(R.layout.log_entry_row, null);
            }
            Log.Entry entry = Log.getEntry(position);
            if (entry != null) {
                TextView timestampText = (TextView)view.findViewById(R.id.log_timestamp_text);
                TextView messageText = (TextView)view.findViewById(R.id.log_message_text);
                timestampText.setText(mDateFormat.format(entry.mTimestamp));
                messageText.setText(entry.mMessage);
            }
            return view;
        }

        @Override
        public int getCount() {
            return Log.getEntryCount();
        }

        @Override
        public Object getItem(int position) {
            return Log.getEntry(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }
    }
}
