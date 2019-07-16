# signer

Example usage:

```
./signer -server-entry <...> -public-key <...> -private-key <...> sign
```

or:

```
SIGNER_SERVER_ENTRY=<...> SIGNER_PUBLIC_KEY=<...> SIGNER_PRIVATE_KEY=<...> ./signer sign
```

* Signer is a tool that adds signatures to encoded server entries (`sign` mode) and generates signing key pairs (`generate` mode).
* In `sign` mode, the output is an copy of the input encoded server entry with an additional `signature` field.
* Inputs may be provided as either command line flags or environment variables.
