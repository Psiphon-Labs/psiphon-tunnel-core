# signer

Example usage:

```
./signer -server-entry $ENCODED_SERVER_ENTRY -public-key $PUBLIC_KEY -private-key $PRIVATE_KEY sign
```

* Signer is a tool that adds signatures to encoded server entries (`sign` mode) and generates signing key pairs (`generate` mode).
* In `sign` mode, the output is an copy of the input encoded server entry with an additional `signature` field.
