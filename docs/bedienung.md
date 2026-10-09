# User guide

## Search

Enter a phone number in any common notation, an IPv4 or IPv6 address, or a hostname. Phone numbers without a
country code use `DEFAULT_REGION`. URLs are accepted and reduced to their hostname, for example
`https://example.org/path` becomes `example.org`.

Network-specific options remain hidden for phone numbers. They appear only after the input contains a period, as
used by IPv4 addresses and hostnames, or a colon for IPv6.

- **Reference date (optional):** adds historical BGP data from RIPEstat, passive DNS from AlienVault OTX, and the
  user's own analysis closest to the selected date. Passive DNS is incomplete; only the provider can establish who
  used a dynamic address at a particular moment.
- **Active-light** (administrators only, registered owned systems only): after explicit authorization confirmation,
  inspect TLS, web metadata, and the selected defensive router profile. Up to four web ports and a short timeout
  can be configured. See [FRITZ!Box Fingerprint](fritzbox-fingerprint.md) and
  [Router Fingerprint](router-fingerprint.md).
- **Port scan** (administrators only): run Nmap against the top 1,000 ports, restricted to entries in
  **Owned systems**. See [Security and operational security](sicherheit.md).

Select **Analyze** to create the analysis and open its detail page.

## History

The start page lists the current user's analyses; administrators see all analyses. Repeated analyses of one query
are grouped into a single entry with a count such as `3×`, showing the latest run. Simultaneously started analyses
are ordered alphabetically. The optional note follows the query, and risk follows the status.

To delete entries, press and hold an analysis or select **Choose**, select further entries, and press **Delete**.
One grouped entry includes every run of that query. Running analyses cannot be deleted until they finish.

## Detail page

- **Toolbar:** edit the persistent note, download a PDF, or repeat the analysis with the same options. PDF and
  repeat actions become available after completion.
- **Other analyses of this query:** expandable list of earlier runs. Each run shows measurable changes from its
  predecessor, such as `abuseipdb_score: 0 → 40`, risk, addresses, or open ports, and provides an **Open** action.
- **Changed since the previous analysis:** appears only when a measurable attribute changed.
- **Language:** the global **DE | EN** switch changes the entire interface, detail page, and downloaded PDF. The
  stored AI report contains both versions and only the selected language is displayed or downloaded. A migration
  removed historical analyses whose AI reports were not bilingual.
- **FRITZ!Box Fingerprint:** negative and uncertain results remain technical raw sources. Only positive evidence is
  included as a report finding. Raw data includes target, authorization, services, TLS, observations, limitations,
  and warnings.
- **Register owned system:** administrators can register an IP target or hostname from its detail page. WAY derives
  suggested current DNS addresses, provider context, and ASNs from existing source data without making another
  request. Target and ASN values remain editable, and saving requires authorization confirmation. Provider is
  documentation; ASNs form a technical safety boundary. If an IP entry has expected ASNs, active enrichment is
  blocked when the address no longer belongs to one of them. An IP entry can also store a confirmed DNS name;
  reverse DNS is only a suggestion, and the name must continue to resolve to that exact IP before active access.
- **Gain more intelligence:** available to administrators after a registered owned target finishes. It creates a
  separate linked run. **Generic router** retrieves only TLS plus headers and the title of `/` on each approved
  port. **FRITZ!Box** additionally requests only `/jason_boxinfo.xml`. **Speedport (experimental)** additionally
  requests only `/data/Status.json`. Profiles run sequentially, do not follow redirects, and never attempt login,
  exploits, or vulnerability probes.
- **Dynamic connections:** register the exact controlled DynDNS or MyFRITZ! hostname instead of a temporary IP,
  together with expected provider ASNs. Before every active check, WAY resolves all current addresses, validates
  them against those ASNs, pins the selected address, and records the time-bound binding in raw data. ISP reverse
  DNS is not proof of ownership.
- **Raw data:** every source can be expanded and copied separately, with **Copy all** for the complete source set.

## Extensions and published main numbers

For German landline numbers, WAY also checks a small number of plausible organization main-number candidates. The
area code remains intact, while the final four or five digits—or exceptionally six digits—are treated as a possible
extension. At least two subscriber-number digits remain in the candidate main number.

Derived search terms are neither stored nor printed in the report. There is no highlighted result card; traceable
evidence remains with its source. The feature is intended to find published main numbers for public authorities,
universities, hospitals, companies, and similar organizations. It is not proof of attribution. Only a published
contact or legal-notice number with source URL, location, and retrieval time supports the main-number relationship.
It proves neither the specific extension nor the identity of a caller. Substring matches inside longer numbers are
discarded. Tests use synthetic data only and make no network requests.

Phone web search uses at most three requests: the formatted exact number, the digits-only form if necessary, and a
main-number or directory query where appropriate. WAY does not attempt to bypass a blocked search engine.

The page updates itself while an analysis runs, showing progress, new sources, and the final report.

## Mobile use

WAY can be installed as a PWA through **Add to Home Screen**. It then appears as **Who Are You** in the mobile share
menu. Sharing a number, link, or contact card (`.vcf`) from the phone or contacts app prefills the search field.
The analysis starts only after selecting **Analyze**, preventing third-party links from triggering requests.

## Accounts

Administrators invite users by email from **Invitations**. Links remain valid for seven days, and the email address
must be confirmed. Users can sign in with their email address or username. Three failed attempts from one client
address cause a one-hour lockout. Password reset works after outbound email has been configured.
