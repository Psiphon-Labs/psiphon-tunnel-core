/*
 * Copyright (c) 2017, Psiphon Inc.
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

package psiphon

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestToAbsoluteURL(t *testing.T) {
	var urlTests = []struct {
		base     string
		relative string
		expected string
	}{
		{"http://example.com/path1?q=p#hash", "relative/path", "http://example.com/relative/path"},
		{"http://example.com/path1?q=p#hash", "relative/path?a=b", "http://example.com/relative/path?a=b"},
		{"http://example.com/path1?q=p#hash", "relative/path#c", "http://example.com/relative/path#c"},
		{"http://example.com/path1?q=p#hash", "relative/path?a=b#c", "http://example.com/relative/path?a=b#c"},
		{"http://example.com/path1/path2?q=p#hash", "relative/path", "http://example.com/path1/relative/path"},
		{"http://example.com/path1/path2?q=p#hash", "/relative/path", "http://example.com/relative/path"},
		{"http://example.com/path1/path2?q=p#hash", "http://example.org/absolute/path", "http://example.org/absolute/path"},
	}

	for _, tt := range urlTests {
		baseURL, _ := url.Parse(tt.base)
		absURL := toAbsoluteURL(baseURL, tt.relative)
		if absURL != tt.expected {
			t.Errorf("toAbsoluteURL(%s, %s): expected %s, actual %s", tt.base, tt.relative, tt.expected, absURL)
		}
	}
}

func TestProxifyURL(t *testing.T) {
	var urlTests = []struct {
		ip            string
		port          int
		urlString     string
		rewriteParams []string
		expected      string
	}{
		{"127.0.0.1", 1234, "http://example.com/media/pl.m3u8?q=p&p=q#hash", []string{"rewriter1"}, "http://127.0.0.1:1234/tunneled-rewrite/http%3A%2F%2Fexample.com%2Fmedia%2Fpl.m3u8%3Fq%3Dp%26p%3Dq%23hash?rewriter1="},
		{"127.0.0.2", 12345, "http://example.com/media/pl.aaa", []string{"rewriter1", "rewriter2"}, "http://127.0.0.2:12345/tunneled-rewrite/http%3A%2F%2Fexample.com%2Fmedia%2Fpl.aaa?rewriter1=&rewriter2="},
		{"127.0.0.3", 12346, "http://example.com/media/bbb", nil, "http://127.0.0.3:12346/tunneled/http%3A%2F%2Fexample.com%2Fmedia%2Fbbb"},
	}

	for _, tt := range urlTests {
		actual := proxifyURL(tt.ip, tt.port, tt.urlString, tt.rewriteParams)
		if actual != tt.expected {
			t.Errorf("proxifyURL(%d, %s, %v): expected %s, actual %s", tt.port, tt.urlString, tt.rewriteParams, tt.expected, actual)
		}
	}
}

func TestRewriteM3U8(t *testing.T) {
	var tests = []struct {
		url                 string
		contentType         string
		contentEncoding     string
		inFilename          string
		expectedFilename    string
		expectedContentType string
		expectError         bool
	}{
		// Relying on file extension to indicate type
		{"http://example.com/test.m3u8", "", "", "testdata/master.m3u8.1", "testdata/master.m3u8.1.target", "application/x-mpegURL", false},
		// No file extension, Content-Type set
		{"http://example.com/test", "application/x-mpegURL", "", "testdata/master.m3u8.1", "testdata/master.m3u8.1.target", "application/x-mpegURL", false},
		// No file extension, Content-Type set
		{"http://example.com/test", "vnd.apple.mpegURL", "", "testdata/master.m3u8.1", "testdata/master.m3u8.1.target", "application/x-mpegURL", false},
		// No file extension, no Content-Type, so no change
		{"http://example.com/test", "", "", "testdata/master.m3u8.1", "testdata/master.m3u8.1", "", false},
		// Media playlist
		{"http://example.com/test.m3u8", "", "", "testdata/media.m3u8.1", "testdata/media.m3u8.1.target", "application/x-mpegURL", false},
		// Complex master playlist
		{"http://example.com/test.m3u8", "", "", "testdata/master.m3u8.2", "testdata/master.m3u8.2.target", "application/x-mpegURL", false},
		// Complex media playlist
		{"http://example.com/test.m3u8", "", "", "testdata/media.m3u8.2", "testdata/media.m3u8.2.target", "application/x-mpegURL", false},
		// Invalid file
		{"http://example.com/test.m3u8", "application/x-mpegURL", "", "httpProxy.go", "httpProxy.go", "", false},
		// Gzipped file
		{"http://example.com/test.m3u8", "", "gzip", "testdata/master.m3u8.1.gz", "testdata/master.m3u8.1.target", "application/x-mpegURL", false},
		// Invalid Gzip file
		{"http://example.com/test.m3u8", "", "gzip", "testdata/master.m3u8.1", "", "", true},
	}

	for i, tt := range tests {
		response := http.Response{
			Request: new(http.Request),
			Header:  http.Header{},
		}

		response.Request.URL, _ = url.Parse(tt.url)
		if tt.contentType != "" {
			response.Header.Set("Content-Type", tt.contentType)
		}
		if tt.contentEncoding != "" {
			response.Header.Set("Content-Encoding", tt.contentEncoding)
		}

		inFile, _ := os.Open(tt.inFilename)
		inFileInfo, _ := inFile.Stat()

		response.Body = inFile
		response.Header.Set("Content-Length", strconv.FormatInt(inFileInfo.Size(), 10))

		err := rewriteM3U8("127.0.0.1", 12345, &response)
		if err != nil {
			if !tt.expectError {
				t.Errorf("rewriteM3U8 returned error: %s", err)
			}
			continue
		}

		rewrittenBody, _ := ioutil.ReadAll(response.Body)
		response.Body.Close()

		expectedBody, _ := ioutil.ReadFile(tt.expectedFilename)

		if !bytes.Equal(rewrittenBody, expectedBody) {
			t.Errorf("rewriteM3U8 body mismatch for test %d", i)
		}

		if tt.expectedContentType != "" && !strings.EqualFold(response.Header.Get("Content-Type"), tt.expectedContentType) {
			t.Errorf("rewriteM3U8 Content-Type mismatch for test %d: %s %s", i, tt.expectedContentType, response.Header.Get("Content-Type"))
		}

		contentLength, _ := strconv.ParseInt(response.Header.Get("Content-Length"), 10, 64)
		if contentLength != int64(len(rewrittenBody)) {
			t.Errorf("rewriteM3U8 Content-Length incorrect for test %d: %d != %d", i, contentLength, len(rewrittenBody))
		}
	}
}
