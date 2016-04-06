Psiphon Tunnel Core Server README
================================================================================

Overview
--------------------------------------------------------------------------------

The `Server` program and the `github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server` package contain an experimental Psiphon server stack.

Functionality is based on the (production server stack)[https://bitbucket.org/psiphon/psiphon-circumvention-system/src/tip/Server/] but only a small subset is implemented. Currently, this stack supports the `SSH` protocol and has a minimal web server to support the API calls the tunnel-core client requires.

Usage
--------------------------------------------------------------------------------

* Execute `Server generate` to generate a server configuration, including new key material and credentials. This will emit a config file and a server entry file.
 * Note: `generate` does not yet take input parameters, so for now you must edit code if you must change the server IP address or ports.
* Execute `Server run` to run the server stack using the generated configuration.
* Copy the contents of the server entry file to the client (e.g., the `TargetServerEntry` config field in the tunnel-core client) to connect to the server.
