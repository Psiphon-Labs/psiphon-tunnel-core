package mar

import (
	"io/ioutil"
	"path"
	"strings"
)

//go:generate go-bindata -ignore (.go|^\.) -o mar.gen.go -pkg mar ./...

var FormatVersions = []string{"20150701", "20150702"}

// Format returns the contents of the named embedded MAR file.
// If the verison is not specified then latest version is returned.
// Returns nil if the format does not exist.
func Format(name, version string) []byte {
	// Return specific version, if specified.
	if version != "" {
		buf, _ := Asset(path.Join("formats", version, name+".mar"))
		return buf
	}

	// Otherwise iterate over versions from newest to oldest.
	for i := len(FormatVersions) - 1; i >= 0; i-- {
		if buf, _ := Asset(path.Join("formats", FormatVersions[i], name+".mar")); buf != nil {
			return buf
		}
	}

	return nil
}

// ReadFormat returns a built-in format, if it exists, or reads from a file.
func ReadFormat(name string) ([]byte, error) {
	// Search built-in first.
	formatName, formatVersion := SplitFormat(name)
	if data := Format(formatName, formatVersion); data != nil {
		return data, nil
	}

	// Otherwise read from file.
	return ioutil.ReadFile(name)
}

// Formats returns a list of available built-in formats.
// Excludes formats that are only to be spawned by other formats.
func Formats() []string {
	return []string{
		"active_probing/ftp_pureftpd_10:20150701",
		"active_probing/http_apache_247:20150701",
		"active_probing/ssh_openssh_661:20150701",
		"dns_request:20150701",
		"dummy:20150701",
		"ftp_simple_blocking:20150701",
		"http_active_probing2:20150701",
		"http_active_probing:20150701",
		"http_probabilistic_blocking:20150701",
		"http_simple_blocking:20150701",
		"http_simple_blocking:20150702",
		"http_simple_blocking_with_msg_lens:20150701",
		"http_simple_nonblocking:20150701",
		"http_squid_blocking:20150701",
		"https_simple_blocking:20150701",
		"nmap/kpdyer.com:20150701",
		"smb_simple_nonblocking:20150701",
		"ssh_simple_nonblocking:20150701",
		"ta/amzn_sess:20150701",
		"udp_test_format:20150701",
		"web_sess443:20150701",
		"web_sess:20150701",
	}
}

// SplitFormat splits a fully qualified format name into it's name and version parts.
func SplitFormat(s string) (name, version string) {
	a := strings.SplitN(s, ":", 2)
	if len(a) == 1 {
		return a[0], ""
	}
	return a[0], a[1]
}

// StripFormatVersion removes any version specified on a format.
func StripFormatVersion(format string) string {
	if i := strings.Index(format, ":"); i != -1 {
		return format[:i]
	}
	return format
}
