# paver

Example usage:

```
./paver -config osl_config.json -key signing_key.pem -offset -1h -period 2h
```

* Paver is a tool that generates OSL files for paving.
* Output is one directory for each propagation channel ID containing the files to upload to the appropriate campaign buckets.
* Each output OSL is empty. Support for specifying and paving server entries is pending.
* The example will pave all OSLs, for each propagation channel ID, within a 2 hour period starting 1 hour ago.
  * `osl_config.json` is the OSL config in `psinet`.
  * `signing_key.pem` is `psinet._PsiphonNetwork__get_remote_server_list_signing_key_pair().pem_key_pair`.
