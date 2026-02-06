# converter

Example usage:

```
PSIPHON_PUSH_PAYLOAD_OBFUSCATION_KEY=<base64> \
PSIPHON_PUSH_PAYLOAD_SIGNATURE_PUBLIC_KEY=<base64> \
PSIPHON_PUSH_PAYLOAD_SIGNATURE_PRIVATE_KEY=<base64> \
./converter -config <config-filename> -TTL <duration> -source <source description> -prioritize <input-filename>
```

* Converter is a tool that converts server lists to and from push payloads. Output is emitted to stdout.
* The type of input file is determined automatically; if the input is a valid server list, it is converted to a push payload; otherwise the input is treated as a push payload and converted to a server list.
* If an optional Psiphon config file input is provided, the key values, except for `PSIPHON_PUSH_PAYLOAD_SIGNATURE_PRIVATE_KEY`, will be read from the config parameters, if present.
* `PSIPHON_PUSH_PAYLOAD_SIGNATURE_PRIVATE_KEY`, `TTL`, `source`, `prioritize`, and optional padding inputs are used only when converting to a push payload.
* Converter does not check individual server entry signatures.
