`transferstats` Package
=======================

This provides a `net.Conn` interface implementation that can be put in a chain
of connections and used to collect transfer statistics for the network traffic
passing through it.

Total bytes transferred is recorded, as well as per-hostname bytes transferred
stats for HTTP and HTTPS traffic (as long as the HTTPS traffic contains [SNI]
information). Which hostnames are recorded is specified by a set of regular
expressions.

[SNI]: https://en.wikipedia.org/wiki/Server_Name_Indication

(TODO: More info.)
