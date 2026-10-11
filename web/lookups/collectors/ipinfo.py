"""IPinfo Lite: country and basic ASN context for public IP addresses."""

import ipaddress

from django.conf import settings


SOURCE = "IPinfo.io Lite (Country/ASN)"
BASE_URL = "https://api.ipinfo.io/lite"
FIELDS = (
    "ip", "asn", "as_name", "as_domain", "country_code", "country",
    "continent_code", "continent", "anycast", "bogon",
)


async def lookup(client, ip):
    """Return only documented Lite fields and keep the token out of the URL."""
    response = await client.get(
        f"{BASE_URL}/{ip}",
        headers={"Authorization": f"Bearer {settings.OSINT_IPINFO_TOKEN}"},
    )
    if response.status_code in (401, 403):
        raise RuntimeError("IPinfo.io rejected the access token")
    if response.status_code == 429:
        raise RuntimeError("IPinfo.io rate limit reached")
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise RuntimeError("IPinfo.io returned an unexpected response")
    returned = data.get("ip")
    if not returned or ipaddress.ip_address(returned) != ipaddress.ip_address(ip):
        raise RuntimeError("IPinfo.io response does not match the requested address")
    result = {field: data[field] for field in FIELDS if field in data}
    result["attribution"] = "Data provided by IPinfo.io"
    result["source_url"] = "https://ipinfo.io/"
    return result
