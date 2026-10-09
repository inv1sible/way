# Router Fingerprint

The detail page can enrich a completed passive analysis with a narrowly selected active profile. The plus icon is
available only to administrators and only when the IP address or hostname is registered under **Owned systems**.
Authorization must be confirmed again before starting. Every active run is stored separately and linked to its
passive parent.

## Profiles

- **Generic router:** for each explicitly approved port, defaulting to `443`, WAY sequentially performs a TLS
  handshake plus HEAD and, for textual content, GET for `/`. It evaluates only status, selected headers, and title.
  Generic words such as “router”, “gateway”, “modem”, or “Speedport” are weak indicators and never justify inventing
  a vendor, model, or firmware version.
- **FRITZ!Box:** uses the same small web budget and additionally requests only `/jason_boxinfo.xml` without
  authentication. See [FRITZ!Box Fingerprint](fritzbox-fingerprint.md).
- **Speedport (experimental):** additionally requests only `/data/Status.json`. WAY retains only explicitly allowed
  model and firmware fields and discards all other status data. It does not attempt login, challenge-response,
  TR-064, or further status endpoints. Availability depends on model, firmware, and WAN configuration, and the
  endpoint is commonly restricted to the LAN.

At most four ports and a timeout of 2–20 seconds are accepted. Redirects are disabled. For a hostname, WAY pins TLS
SNI and HTTP Host to the previously validated IP address. Raw data records the execution rules in `requestPolicy`.

## Deliberate exclusions

WAY performs no login attempts, credential submission, brute force, automatic port discovery, SOAP action,
exploit, CVE probe, or vulnerability test. It never automatically follows a response to another host. An active
check creates a few ordinary web requests and can therefore appear in target logs. Third-party systems remain
passive-only.

An open web port may be forwarded to another internal device. With IPv6, the investigated address itself may
belong to an internal device rather than the router. Without an externally reachable service, the firmware version
normally cannot be determined.
