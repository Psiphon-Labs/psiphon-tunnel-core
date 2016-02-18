[![Build Status](https://travis-ci.org/Psiphon-Labs/psiphon-tunnel-core.png)](https://travis-ci.org/Psiphon-Labs/psiphon-tunnel-core) [![Coverage Status](https://coveralls.io/repos/github/Psiphon-Labs/psiphon-tunnel-core/badge.svg?branch=master)](https://coveralls.io/github/Psiphon-Labs/psiphon-tunnel-core?branch=master)

Psiphon 3 Tunnel Core README
================================================================================

Overview
--------------------------------------------------------------------------------

A Psiphon client component implemented in Go. This component provide core tunnel functionality, handling all aspects of connecting to Psiphon servers and relaying traffic through those servers. Local proxies provide an interface for routing traffic through the tunnel.

This component does not include a UI and does not handle capturing or routing local traffic. These major aspects are handled by other parts of Psiphon client applications.

Status
--------------------------------------------------------------------------------

This project is currently at the proof-of-concept stage. Current production Psiphon client code is available at our [Psiphon 3 repository](https://bitbucket.org/psiphon/psiphon-circumvention-system).

Setup
--------------------------------------------------------------------------------

#### Build

* Go 1.5 (or higher) is required.
* This project builds and runs on recent versions of Windows, Linux, and Mac OS X.
* Note that the `psiphon` package is imported using the absolute path `github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon`; without further local configuration, `go` will use this version of the code and not the local copy in the repository.
* In this repository, run `go build` in `ConsoleClient` to make the `ConsoleClient` binary, a console Psiphon client application.
  * Build versioning info may be configured as follows, and passed to `go build` in the `-ldflags` argument:

    ```
    BUILDDATE=$(date --iso-8601=seconds)
    BUILDREPO=$(git config --get remote.origin.url)
    BUILDREV=$(git rev-parse HEAD)
    LDFLAGS="\
    -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildDate=$BUILDDATE \
    -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRepo=$BUILDREPO \
    -X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon.buildRev=$BUILDREV \
    "
    ```

#### Configure

 * Configuration files are standard text files containing a valid JSON object. Example:


  <!--BEGIN-SAMPLE-CONFIG-->
  ```
  {
      "PropagationChannelId" : "<placeholder>",
      "SponsorId" : "<placeholder>",
      "LocalHttpProxyPort" : 8080,
      "LocalSocksProxyPort" : 1080
  }
  ```
  <!--END-SAMPLE-CONFIG-->

*Note: The lines `<!--BEGIN-SAMPLE-CONFIG-->` and `<--END-SAMPLE-CONFIG-->` (visible in the raw Markdown) are used by the [config test](psiphon/config_test.go). Do not remove them.*

* All config file parameters are [documented here](https://godoc.org/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon#Config).
* Replace each `<placeholder>` with a value from your Psiphon server. The Psiphon server-side stack is open source and can be found in our [Psiphon 3 repository](https://bitbucket.org/psiphon/psiphon-circumvention-system).


#### Run

* Run `./ConsoleClient --config psiphon.config` where `psiphon.config` is created as described in the [Configure](#configure) section above


Other Platforms
--------------------------------------------------------------------------------

* The project builds and runs on Android. See the [AndroidLibrary README](AndroidLibrary/README.md) for more information about building the Go component, and the [AndroidApp README](AndroidApp/README.md) for a sample Android app that uses it.


Licensing
--------------------------------------------------------------------------------

Please see the LICENSE file.


Contacts
--------------------------------------------------------------------------------

For more information on Psiphon Inc, please visit our web site at:

[www.psiphon.ca](http://www.psiphon.ca)
