BrowserDemo
===========

This is the browser demonstration page

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

## Installation (Docker)

For this demo, please we will use the v0.1 Docker image. You'll need to have Docker
installed. You can find instructions for specific operating system here:
https://docs.docker.com/install

Once docker is installed, then download the appropriate docker file from the v0.1 release of Marionette.  The file can be found here:

https://github.com/redjack/marionette/releases/tag/v0.1

To install the docker file in docker:

```
$ gunzip redjack-marionette-0.1.gz
```
```
$ docker load -i redjack-marionette-0.1
```

### Running using the Docker image

Next, run the Docker image and use the appropriate port mappings for the
Marionette format you're using. `http_simple_blocking` uses
port `8081`:

```sh
$ docker run -p 8081:8081 redjack/marionette server -format http_simple_blocking
```

```sh
$ docker run -p 8079:8079 redjack/marionette client -bind 0.0.0.0:8079 -format http_simple_blocking
```

If you're running _Docker for Mac_ then you'll also need to add a `-server` argument:

```sh
$ docker run -p 8079:8079 redjack/marionette client -bind 0.0.0.0:8079 -server docker.for.mac.host.internal -format http_simple_blocking
```

Start wireshark on the loopback network and watch the packets.

(Note, if wireshark is not displaying the packets as HTTP, go to:

``WireShark > Preferences > Protocols > HTTP``
 
 and add port 8081 to the port list.

### Surf

Look at your favorite webpage(s).  The system is fairly reliable now, but in the event that the connection drops, then:

- Stop the server and the client
- Restart the server and the client (in order)
- Refresh the page
- Report the error
