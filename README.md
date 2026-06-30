<h1 align="center" style="border-bottom: none">
    RFC2136 Dynamic DNS Provider
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-production-3D1973?style=flat-square" alt="Integration Status: production" />
<a href="https://github.com/Keyfactor/rfc2136-dnsplugin/actions/workflows/keyfactor-starter-workflow.yml"><img src="https://github.com/Keyfactor/rfc2136-dnsplugin/actions/workflows/keyfactor-starter-workflow.yml/badge.svg" alt="Build" /></a>
<a href="https://github.com/Keyfactor/rfc2136-dnsplugin/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/rfc2136-dnsplugin?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/rfc2136-dnsplugin?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/rfc2136-dnsplugin/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a>
  ·
  <a href="#requirements">
    <b>Requirements</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=dnsplugin">
    <b>Related Integrations</b>
  </a>
</p>

## Overview

The RFC2136 Dynamic DNS Provider plugin enables automated DNS-based domain validation for Keyfactor certificate lifecycle management against any DNS server that supports RFC 2136 dynamic updates. This includes BIND, Microsoft DNS, PowerDNS, Knot DNS, and most enterprise authoritative DNS servers. The plugin authenticates dynamic update requests using TSIG (RFC 2845) shared-key cryptography.

## Features

- Automated DNS TXT record creation and deletion in RFC2136 Dynamic DNS
- Configurable DNS propagation timeouts and retry behavior
- TSIG-authenticated dynamic updates (HMAC-SHA256 by default; SHA-512/SHA-1/MD5 also supported)
- Works with any RFC 2136 compliant DNS server (BIND, Microsoft DNS, PowerDNS, Knot DNS, etc.)
- Operates on-prem or in air-gapped environments — no cloud dependency
- Zone-scoped: the plugin writes only to the zone you configure

## Requirements

### Keyfactor Platform
- Keyfactor AnyCA Gateway REST **26.2 or later** (DNS validation support was added in AnyCA Gateway 26.2)
- A gateway product that supports DNS-01 domain validation (ACME REST Gateway, DigiCert, Sectigo, etc.)

### RFC2136 Dynamic DNS Requirements

- A DNS server that supports RFC 2136 dynamic updates with TSIG authentication
- A TSIG key configured on the DNS server and exported in base64 form
- The DNS server's zone must permit dynamic updates from the TSIG key (e.g. BIND `update-policy` or `allow-update`)
- Network reachability from the gateway server to the DNS server's UDP/TCP port (default 53)

### Runtime Requirements
- .NET 10.0 runtime (provided by the gateway server)
- Network connectivity to the configured DNS server (HTTPS/443)

## Installation

This plugin is installed alongside any Keyfactor gateway server that supports DNS-01 domain validation (ACME REST Gateway, DigiCert, Sectigo, etc.). The same DLL works with every supported gateway.

> See the official Keyfactor AnyCA Gateway REST installation documentation for the authoritative install instructions: **<TBD link from Sarah Duncan>**. The steps below are a general guide; defer to the official docs if they diverge.

### 1. Download the Plugin

Download the latest release from the [Releases](https://github.com/Keyfactor/rfc2136-dnsplugin/releases) page.

### 2. Copy the plugin DLLs to the gateway's Extensions folder

On the server hosting your gateway, unzip the release and copy the contents of the `net10.0` directory into the gateway's `Extensions` folder.

**Windows** (example path — substitute the gateway product folder for your install):

```text
C:\Program Files\Keyfactor\<GatewayName>\AnyGatewayREST\net10.0\Extensions\
```

**Linux**:

```text
/opt/keyfactor/<gateway-name>/AnyGatewayREST/net10.0/Extensions/
```

Replace `<GatewayName>` (or `<gateway-name>` on Linux) with the gateway you are installing into (e.g. `AcmeGwDns`, `DigiCert`, `Sectigo`).

### 3. Restart the gateway service

Restart the AnyGatewayREST Windows service for the gateway you installed the plugin into so the Extensions folder is rescanned.

## Configuration

After installing the plugin DLL into the gateway's Extensions folder, configure a new DNS Provider entry in the AnyCA Gateway REST UI and select **RFC2136 Dynamic** as the provider type. See the official Keyfactor AnyCA Gateway REST documentation for the canonical UI walkthrough: **<TBD link from Sarah Duncan>**.

### RFC2136 Dynamic DNS Setup

#### BIND

Generate a TSIG key and grant it permission to update the zone:

```bash
# Generate a key on the DNS server
tsig-keygen -a hmac-sha256 keyfactor-acme. > /etc/bind/keyfactor-acme.key

# View the secret to copy into Rfc2136_TsigKey
cat /etc/bind/keyfactor-acme.key
```

Reference the key in `named.conf` and grant zone update permission:

```text
include "/etc/bind/keyfactor-acme.key";

zone "example.com" {
    type master;
    file "/etc/bind/db.example.com";
    update-policy {
        grant keyfactor-acme. name _acme-challenge.example.com. TXT;
        grant keyfactor-acme. name *._acme-challenge.example.com. TXT;
    };
};
```

Reload BIND (`rndc reload`) and confirm the zone accepts updates.

#### Microsoft DNS

On Windows DNS Server, set the zone to allow secure dynamic updates and configure the same TSIG shared-secret in your DNS zone via PowerShell or `dnscmd`. Microsoft DNS supports RFC 2136 dynamic updates through TSIG when the secure-update setting permits it.

### Configuration Parameters

| Parameter | Description | Required | Example |
|-----------|-------------|----------|---------|
| `Rfc2136_Server` | DNS server hostname or IP address that accepts RFC 2136 dynamic updates. | Yes | `ns1.example.com` |
| `Rfc2136_Port` | DNS server port. Defaults to 53. | No | `53` |
| `Rfc2136_Zone` | DNS zone (origin) into which TXT records will be written. | Yes | `example.com` |
| `Rfc2136_TsigKeyName` | Name of the TSIG key configured on the DNS server (as it appears in named.conf or equivalent). | Yes | `keyfactor-acme` |
| `Rfc2136_TsigKey` | Base64-encoded TSIG key value. Pair with the key name configured on the DNS server. | Yes | ` ` |
| `Rfc2136_TsigAlgorithm` | TSIG algorithm. Common values: hmac-sha256 (default), hmac-sha512, hmac-sha1, hmac-md5. | No | `hmac-sha256` |
| `PropagationWaitSeconds` | Seconds to wait for DNS propagation between record creation and verification | No | `60` |
| `MaxWaitSeconds` | Maximum total seconds to wait for DNS propagation before failing | No | `300` |
| `RetryAttempts` | Number of retry attempts for transient API errors | No | `3` |

### Example Configuration

**Standard configuration with TSIG:**

```json
{
  "Rfc2136_Server": "ns1.example.com",
  "Rfc2136_Port": "53",
  "Rfc2136_Zone": "example.com",
  "Rfc2136_TsigKeyName": "keyfactor-acme",
  "Rfc2136_TsigKey": "your-base64-encoded-secret",
  "Rfc2136_TsigAlgorithm": "hmac-sha256",
  "PropagationWaitSeconds": 30,
  "MaxWaitSeconds": 120,
  "RetryAttempts": 3
}
```

## Usage

### Automatic Domain Validation

Once configured, the plugin automatically handles DNS validation during certificate enrollment and renewal:

1. **Record Creation**: Plugin creates a DNS TXT record with the validation challenge
2. **Propagation Wait**: Plugin waits for DNS propagation (configurable timeout)
3. **Verification**: Plugin verifies the record exists on RFC2136 Dynamic DNS nameservers
4. **Cleanup**: Plugin deletes the validation record after successful validation

### Zone Discovery

Unlike cloud-based DNS providers, the RFC2136 plugin does **not** auto-discover zones. Configure the exact `Rfc2136_Zone` that the TSIG key is authorized to update. If multiple zones need validation, configure a separate domain validation provider entry per zone.

### Testing Connectivity

Test the TSIG update path end-to-end using `nsupdate`:

```bash
nsupdate -y "hmac-sha256:keyfactor-acme:your-base64-encoded-secret" <<EOF
server ns1.example.com 53
zone example.com
update add _acme-challenge.example.com. 60 TXT "test-value"
send
quit
EOF

# Verify the record was added
dig @ns1.example.com TXT _acme-challenge.example.com +short

# Clean up
nsupdate -y "hmac-sha256:keyfactor-acme:your-base64-encoded-secret" <<EOF
server ns1.example.com 53
zone example.com
update delete _acme-challenge.example.com. TXT
send
quit
EOF
```

## Troubleshooting

### Common Issues

**Authentication Failures**

Symptom: `tsig verify failure (BADKEY/BADSIG)`

- Verify the TSIG key name on the gateway matches the key name on the DNS server (case-sensitive, trailing dot optional)
- Confirm the base64-encoded secret has no surrounding whitespace
- Verify the TSIG algorithm matches what is configured on the DNS server (`hmac-sha256` is the standard default)
- Check that clock skew between the gateway and DNS server is under a few minutes — TSIG signatures include a timestamp

**Insufficient Permissions**

Symptom: `update failed: REFUSED`

- The DNS server is refusing the update. Check the zone's `update-policy` (BIND) or equivalent setting — it must grant the TSIG key permission to write the specific record type (typically TXT) under `_acme-challenge.<domain>`
- Some configurations restrict updates by source IP in addition to TSIG — confirm the gateway server's IP is allowed

**No Response / Timeout**

Symptom: `timed out waiting for update response`

- Verify network reachability from the gateway server to the DNS server on UDP/53 (and TCP/53 for large updates)
- Check for firewalls or security groups dropping the update packets
- Confirm the DNS server is configured to listen on the address being targeted

### Logging

Enable debug logging in the gateway's logging configuration:

```json
{
  "Logging": {
    "LogLevel": {
      "Keyfactor.Extensions.DomainValidator.Rfc2136": "Debug"
    }
  }
}
```

## Support

The RFC2136 Dynamic DNS Provider plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com.

### Resources

- [RFC2136 Dynamic DNS Documentation](https://datatracker.ietf.org/doc/html/rfc2136)
- [Report Issues](https://github.com/Keyfactor/rfc2136-dnsplugin/issues)
- [Discussions](https://github.com/Keyfactor/rfc2136-dnsplugin/discussions)

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor DNS Provider plugins](https://github.com/orgs/Keyfactor/repositories?q=dnsplugin).
