marionette
==========

## Testing the Binary

First start the server proxy on your server machine and forward traffic to a server
such as `google.com`.

```sh
$ marionette server -format http_simple_blocking -proxy google.com:80
listening on [::]:8081, proxying to google.com:80
```
This has launched the server process.  The server is now waiting for a client connection.

Leave the server process running and start the client proxy on your client machine and connect to your server proxy.
Replace `$SERVER_IP` with the IP address of your server.

```sh
$ marionette client -format http_simple_blocking -server $SERVER_IP
listening on 127.0.0.1:8079, connected to <SERVER_IP>
```
Now the client process has started and is waiting for traffic at 127.0.0.1:8079 to forward to the server.

Finally, send a `curl` to `127.0.0.1:8079` and you should see a response from
`google.com`:

```sh
$ curl 127.0.0.1:8079
```
## Browser Setup

Testing Marionette is best done through the Firefox browser.  If you do not have a copy of Firefox, download it [here](https://www.mozilla.org/en-US/firefox/new/).

### Activate the Proxy

Go to:

``Firefox > Preferences > General > Network Proxy``

- Set the proxy button to Manual Proxy Configuration.
- Set the SOCKS host to the machine to the incoming port on the Marionette client (Probably localhost and port 8079)
- Make sure that the SOCKS v5 Radio button is depressed.
- Check the box marked "Proxy DNS when using SOCKS v5"

### Secure the DNS

Although the code can work through the proxy with the above data, Firefox does not yet have its DNS fully going through the proxy.  To fix this:

- Type about:config into the search bar.  This will open the advanced settings for the browser.
- Go to the term media.peerconnection.enabled 
- Set it to false by double clicking on it.

## Testing the Browser

First start the server proxy on your server machine and forward traffic to a server
such as `google.com`.

```sh
$ marionette server -format http_simple_blocking -socks5
listening on [::]:8081, proxying via socks5
```
Note that, unlike before, we do not use a -proxy command line option, but instead use -socks5 option.  This starts a general socks5 proxy server that internet connections can pass through.

This has launched the server process.  The server is now waiting for a client connection.

Leave the server process running and start the client proxy on your client machine and connect to your server proxy.
Replace `$SERVER_IP` with the IP address of your server.

```sh
$ marionette client -format http_simple_blocking -server $SERVER_IP
listening on 127.0.0.1:8079, connected to <SERVER_IP>
```
Now the client process has started and is waiting for traffic at 127.0.0.1:8079 to forward to the server.

Now start the Firefox browser as earlier configured.  You will now be able to surf the web.