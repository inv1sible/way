# FRITZ!Box Fingerprint

WAY adds the structured **FRITZ!Box Fingerprint** source to IP-address and hostname analyses. It defensively
assesses whether a publicly reachable target is likely to be a FRITZ!Box. The result is a current observation—or,
for search-engine data, a potentially stale third-party observation—not proof of ownership or a vulnerability test.

## Usage and authorization

Enter an IP address or hostname in the search field. The default **passive** mode does not contact the target. It
evaluates reverse DNS and already configured Shodan InternetDB and Censys results for explicit AVM or FRITZ!
markers. Censys remains optional and uses the existing `CENSYS_TOKEN`; no mandatory API dependency was added.

Only administrators can select **Active-light**. The target must also be registered under **Owned systems**, and
the administrator must explicitly confirm ownership or authorization. Between one and four ports and a timeout of
2–20 seconds can be configured. Without explicit ports, WAY checks only `443` and `8443`. Ports `80` and `8080`
use HTTP; every other explicitly approved port uses HTTPS. Repeat analysis preserves these settings. A passive
analysis can later be enriched as a separate linked run through **Gain more intelligence**.

Active requests run strictly sequentially per port. WAY first uses HEAD to inspect content type and performs GET
only for textual responses, with no more than four HTTP requests per port:

1. `/` for status, selected headers, and optionally the page title;
2. `/jason_boxinfo.xml` for device information publicly available without authentication.

WAY performs no login, sends no credentials, invokes no SOAP action, and performs no brute-force, exploit, CVE,
or automatic port scan. Redirects are disabled. WAY's separately authorized Nmap scan remains independent and is
restricted to registered owned systems. Nmap service detection is documented in the
[Nmap reference](https://nmap.org/book/man-version-detection.html).

## Target binding and privacy

- IP literals and hostnames are normalized and strictly validated.
- Active access accepts publicly routable targets only. Loopback, private, reserved, link-local, multicast, CGNAT,
  documentation, and cloud-metadata addresses are rejected.
- For hostnames, every A and AAAA result must be public. A single mixed private address blocks active access.
- The validated address is passed to the tool service and validated again. `curl --resolve` pins the HTTP Host and
  TLS SNI names to that exact address, preventing a second DNS lookup during the connection. IPv6 literals are
  enclosed correctly in URL brackets.
- Self-signed certificates can be processed for fingerprinting and are marked untrusted. TLS validation is not
  disabled globally.
- Response bodies are limited to 64 KiB, and binary content is not processed. XML containing a DTD or entities is
  rejected. Raw device XML is neither stored nor logged.
- Device serial numbers contained in BoxInfo are always discarded. WAY currently has no separate secure output
  mode for this sensitive value.

## Result and confidence

The raw source contains `target`, `authorization`, `classification`, `device`, `services`, `tls`, `observations`,
`limitations`, `warnings`, and a readable `summary`. Missing values remain `null`. Negative and uncertain results
remain raw technical data and are not highlighted in the AI report. Positive evidence can appear in its German
and English versions.

```json
{
  "classification": {
    "likelyFritzBox": true,
    "confidence": "high",
    "reasons": ["/jason_boxinfo.xml returned a plausible BoxInfo document; the device serial number was discarded."]
  },
  "device": {
    "model": "FRITZ!Box 7590 AX",
    "hardwareId": "259",
    "fritzOsVersion": "8.02",
    "rawFirmwareVersion": "259.08.02-123456",
    "revision": "123456",
    "oem": "avm",
    "language": "en",
    "labBuild": "Lab"
  }
}
```

`high` requires a plausible, successfully parsed BoxInfo document. `medium` requires several independent sources,
`low` represents one weak indicator, and `none` means that no defensible evidence was found. Model and exact
firmware versions are copied only from directly supplied fields. The raw version is preserved, and a FRITZ!OS
version is derived only from an unambiguous AVM format.

Responses such as `401`, `403`, `404`, timeout, login HTML, malformed XML, and oversized XML are normal negative
results. `/jason_boxinfo.xml` is not available on every FRITZ!Box or through every WAN configuration. AVM documents
its model-dependent interfaces at [FRITZ! interfaces](https://fritz.com/pages/schnittstellen).

## Limitations

- A public IPv4 address may terminate at the provider because of CGNAT or DS-Lite.
- An open port may be forwarded to another internal device.
- With IPv6, the investigated address may belong to an internal device rather than the FRITZ!Box.
- Firmware normally cannot be identified externally when no WAN service is reachable.
- Shodan and Censys observations can be stale; WAY therefore records observation or retrieval time and the
  corresponding limitation.

This feature is exclusively for systems you own or are explicitly authorized to test.
