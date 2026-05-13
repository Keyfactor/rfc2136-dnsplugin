## Overview

The RFC2136 Dynamic DNS Provider plugin enables automated DNS-based domain validation for Keyfactor certificate lifecycle management against any DNS server that supports RFC 2136 dynamic updates. This includes BIND, Microsoft DNS, PowerDNS, Knot DNS, and most enterprise authoritative DNS servers. The plugin authenticates dynamic update requests using TSIG (RFC 2845) shared-key cryptography.

## Features

- TSIG-authenticated dynamic updates (HMAC-SHA256 by default; SHA-512/SHA-1/MD5 also supported)
- Works with any RFC 2136 compliant DNS server (BIND, Microsoft DNS, PowerDNS, Knot DNS, etc.)
- Operates on-prem or in air-gapped environments — no cloud dependency
- Zone-scoped: the plugin writes only to the zone you configure

## Requirements

- A DNS server that supports RFC 2136 dynamic updates with TSIG authentication
- A TSIG key configured on the DNS server and exported in base64 form
- The DNS server's zone must permit dynamic updates from the TSIG key (e.g. BIND `update-policy` or `allow-update`)
- Network reachability from the gateway server to the DNS server's UDP/TCP port (default 53)
