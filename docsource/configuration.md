### Provider Setup

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

### Example Configurations

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

### Troubleshooting

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
