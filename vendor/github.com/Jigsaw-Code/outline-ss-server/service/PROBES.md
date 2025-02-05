# Outline Shadowsocks Probing and Replay Defenses

## Attacks

To ensure that proxied connections have not been modified in transit, the Outline implementation of Shadowsocks only supports modern [AEAD cipher suites](https://shadowsocks.org/en/spec/AEAD-Ciphers.html).  This protects users from a wide range of potential attacks.  However, even with [AEAD's authenticity guarantees](https://en.wikipedia.org/wiki/Authenticated_encryption), there are still ways for an attacker to abuse the Shadowsocks protocol.

One category of attacks are "probing" attacks, in which the adversary sends test data to the proxy in order to confirm that it is actually a Shadowsocks proxy.  This is a violation of the Shadowsocks security design, which is intended to ensure that only an authenticated user can identify the proxy.  For example, one [probing attack against Shadowsocks](https://scholar.google.com/scholar?cluster=8542824533765048218) sends different numbers of random bytes to a target server, and identifies how many bytes the server reads before detecting an error and closing the connection.  This number can be distinctive, identifying the server software.

Another [reported](https://gfw.report/blog/gfw_shadowsocks/) category of attacks are "replay" attacks, in which an adversary records a conversation between a Shadowsocks client and server, then replays the contents of that connection.  The contents are valid Shadowsocks AEAD data, so the proxy will forward the connection to the specified destination, as usual.  In some cases, this can cause a duplicated action (e.g. uploading a file twice with HTTP POST).  However, modern secure protocols such as HTTPS are not replayable, so this will normally have no ill effect.

A greater concern for Outline is the use of replays in probing attacks to identify Shadowsocks proxies.  By sending modified and unmodified replays, an attacker might be able to confirm that a server is in fact a Shadowsocks proxy, by observing distinctive behaviors.

## Outline's defenses

Outline contains several defenses against probing and replay attacks.

### Invalid probe data

If Outline detects that the initial data is invalid, it will continue to read data (exactly as if it were valid), but will not reply, and will not close the connection until a timeout.  This leaves the attacker with minimal information about the server.

### Client replays

When client replay protection is enabled, every incoming valid handshake is reduced to a 32-bit checksum and stored in a hash table.  When the table is full, it is archived and replaced with a fresh one, ensuring that the recent history is always in memory.  Using 32-bit checksums results in a false-positive detection rate of 1 in 4 billion for each entry in the history.  At the maximum history size (two sets of 20,000 checksums each), that results in a false-positive failure rate of 1 in 100,000 sockets ... still far lower than the error rate expected from network unreliability.

This feature is on by default in Outline.  Admins who are using outline-ss-server directly can enable this feature by adding "--replay_history 10000" to their outline-ss-server invocation.  This costs approximately 20 bytes of memory per checksum.

### Server replays

Shadowsocks uses the same Key Derivation Function for both upstream and downstream flows, so in principle an attacker could record data sent from the server to the client, and use it in a "reflected replay" attack as simulated client->server data.  The data would appear to be valid and authenticated to the server, but the connection would most likely fail when attempting to parse the destination address header, perhaps leading to a distinctive failure behavior.

To avoid this class of attacks, outline-ss-server uses an [HMAC](https://en.wikipedia.org/wiki/HMAC) with a 32-bit tag to mark all server handshakes, and checks for the presence of this tag in all incoming handshakes.  If the tag is present, the connection is a reflected replay, with a false positive probability of 1 in 4 billion.

## Metrics

Outline provides server operators with metrics on a variety of aspects of server activity, including any detected attacks.  To observe attacks detected by your server, look at the `tcp_probes` histogram vector in Prometheus.  The `status` field will be `"ERR_CIPHER"` (indicating invalid probe data), `"ERR_REPLAY_CLIENT"`, or `"ERR_REPLAY_SERVER"`, depending on the kind of attack your server observed.  You can also see approximately how many bytes were sent before giving up.
