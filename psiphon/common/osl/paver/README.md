# paver

Example usage:

```
./paver -config osl_config.json -key signing_key.pem -count 3
```

* Paver is a tool that generates OSL files for paving.
* Output is one directory for each propagation channel ID containing the files to upload to the appropriate campaign buckets.
* Each output OSL is empty. Support for specifying and paving server entries is pending.
* The example will pave 3 OSLs (e.g., OSLs for 3 time periods from epoch, where the time period is determined by the config) for each propagation channel ID.
  * `osl_config.json` is the OSL config in `psinet`.
  * `signing_key.pem` is `psinet._PsiphonNetwork__get_remote_server_list_signing_key_pair().pem_key_pair`.

