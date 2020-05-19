## Psiphon Tunnel Obfuscated Server Lists

### Design

Obfuscated server lists (OSLs) is a mechanism to distribute Psiphon servers to select users. Like standard server lists, these server lists are publicly available at locations encoded in the Psiphon client. Unlike standard server lists, these lists are encrypted. Only clients that have the required keys can access the servers within these lists.

One scheme for issuing server list encryption keys (SLOKs) is for the Psiphon servers to release the keys to clients that meet certain criteria for data transfer. The criteria is designed to distinguish regular, typical users from bots, scripts, and opportunistic adversaries.
The data transfer SLOK scheme uses thresholds and groups of criteria to avoid being too strict. This serves two purposes: users don't need to meet all targets to earn a SLOK; and knowing that a user has earned a SLOK does not precisely reveal the user's activity.

Parameters include:
- The base time period for each SLOK. For example, with a base time period of one week, any sufficient network activity within a given week would earn the SLOKs. Possession of the SLOK does not reveal when, within the week the network, activity took place.
- A set of network destinations for each SLOK, and a threshold. For example, sufficient data transfer to any 2 of 5 of a group of different network destinations, which could be defined to include typical "search", "social media", "messaging", "news", "e-commerce" destinations. Possession of the SLOK does not reveal which of the groups were visited; nor exactly which sites within the groups. Furthermore, the definition of network destinations admits all sites hosted on shared infrastructure, introducing further ambiguity.
- A time threshold on top of SLOKs. For example, any 2 of 4 weekly SLOKs are required to decrypt a given OSL. Decrypting the OSL and using its servers does not reveal exactly which SLOKs were used.
- A propagation channel ID for each SLOK. Each propagation channel has its own SLOK key space, and an adversary in possession of a SLOK from a different propagation channel cannot use that to determine the properties of SLOKs from other propagation channels.

All parameters and criteria are operational secrets stored only in Psiphon servers/automation and not publicly revealed.

Client progress towards a SLOK is stored in Psiphon server volatile memory (and, potentially, swap).

When a SLOK is earned by a client, the Psiphon server sends the SLOK to the client through the secure Psiphon SSH tunnel. No logs are recorded for individual SLOK events.

The client stores all its SLOKs in its local database. SLOKs are random values. An adversary that compromises a client may obtain the SLOKs, but does not have access to the parameters which generated the SLOK. And even if the parameters are compromised (or the adversary reverse engineers partial parameter information by earning its own SLOKs via random activity) the thresholds and groupings within the parameters mean a single SLOK does not demonstrate browsing a particular site or browsing at a particular time.

When an OSL is downloaded, this event is logged. This is how we monitor the mechanism. This log is a standard Psiphon log, which does not record the client IP address but does record GeoIP information. A log that an OSL has been unlocked indirectly reveals that a client has sufficient SLOKs, earned through the various criteria. But this is much less specific than, for example, a domain bytes transferred log.
