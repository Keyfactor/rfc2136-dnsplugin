// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0
using System.Net;
using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using ARSoft.Tools.Net.Dns.DynamicUpdate;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using ArDnsClient = ARSoft.Tools.Net.Dns.DnsClient;

namespace Keyfactor.Extensions.DomainValidator.Rfc2136
{
    /// <summary>
    /// RFC 2136 Dynamic DNS Update provider for BIND and Microsoft DNS servers.
    /// Uses ARSoft.Tools.Net for TSIG authentication.
    /// </summary>
    internal class Rfc2136DnsProvider
    {
        private static readonly ILogger _logger = LogHandler.GetClassLogger<Rfc2136DnsProvider>();

        private readonly string _serverHost;
        private readonly int _serverPort;
        private readonly string _zoneName;
        private readonly string _tsigKeyName;
        private readonly byte[] _tsigKey;
        private readonly TSigAlgorithm _tsigAlgorithm;

        public Rfc2136DnsProvider(
            string serverHost,
            string zoneName,
            string tsigKeyName,
            string tsigKeyValue,
            string tsigAlgorithm = "hmac-sha256",
            int serverPort = 53)
        {
            _serverHost = serverHost ?? throw new ArgumentNullException(nameof(serverHost));
            _zoneName = zoneName?.TrimEnd('.') ?? throw new ArgumentNullException(nameof(zoneName));
            _tsigKeyName = tsigKeyName ?? throw new ArgumentNullException(nameof(tsigKeyName));
            _tsigKey = Convert.FromBase64String(tsigKeyValue ?? throw new ArgumentNullException(nameof(tsigKeyValue)));
            _tsigAlgorithm = ParseTsigAlgorithm(tsigAlgorithm);
            _serverPort = serverPort;
        }

        public async Task<bool> CreateRecordAsync(string recordName, string txtValue)
        {
            try
            {
                var cleanName = recordName.TrimEnd('.');
                _logger.LogDebug("[RFC2136] Creating TXT record: {RecordName} = {TxtValue}", cleanName, txtValue);

                await DeleteRecordAsync(recordName);

                var serverAddress = await ResolveServerAddressAsync();
                var msg = new DnsUpdateMessage { ZoneName = DomainName.Parse(_zoneName) };

                var domainName = DomainName.Parse(cleanName);
                msg.Updates.Add(new AddRecordUpdate(new TxtRecord(domainName, 60, txtValue)));

                msg.TSigOptions = new TSigRecord(
                    DomainName.Parse(_tsigKeyName),
                    _tsigAlgorithm,
                    DateTime.Now,
                    new TimeSpan(0, 5, 0),
                    msg.TransactionID,
                    ReturnCode.NoError,
                    null,
                    _tsigKey);

                _logger.LogDebug("[RFC2136] Sending update to {Server}:{Port}", serverAddress, _serverPort);
                var client = new ArDnsClient(serverAddress, _serverPort);
                var response = await client.SendUpdateAsync(msg);

                if (response == null)
                {
                    _logger.LogError(
                        "[RFC2136] No response received from DNS server {Server}:{Port} while creating TXT record '{RecordName}' in zone '{Zone}'. The server may be unreachable, refusing TCP/UDP 53, or dropping TSIG-signed updates.",
                        _serverHost, _serverPort, cleanName, _zoneName);
                    throw new InvalidOperationException(
                        $"RFC2136 DNS update failed: no response from server {_serverHost}:{_serverPort} creating TXT record '{cleanName}' in zone '{_zoneName}'. Verify the server is reachable and accepts dynamic updates.");
                }

                if (response.ReturnCode == ReturnCode.NoError)
                {
                    _logger.LogInformation("[RFC2136] Successfully created TXT record: {RecordName}", cleanName);
                    return true;
                }

                _logger.LogError(
                    "[RFC2136] Failed to create TXT record '{RecordName}' in zone '{Zone}' on {Server}:{Port}. Return code: {ReturnCode}.",
                    cleanName, _zoneName, _serverHost, _serverPort, response.ReturnCode);
                throw new InvalidOperationException(
                    $"RFC2136 DNS update to create TXT record '{cleanName}' in zone '{_zoneName}' on {_serverHost}:{_serverPort} failed with return code '{response.ReturnCode}'. " +
                    "A REFUSED/NOTAUTH code usually indicates a TSIG key/zone mismatch or the server not being authoritative for the zone.");
            }
            catch (InvalidOperationException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[RFC2136] Error creating TXT record for {RecordName} in zone '{Zone}' on {Server}:{Port}", recordName, _zoneName, _serverHost, _serverPort);
                throw new InvalidOperationException(
                    $"RFC2136 DNS provider error creating TXT record '{recordName}' in zone '{_zoneName}' on {_serverHost}:{_serverPort}: {ex.Message}", ex);
            }
        }

        public async Task<bool> DeleteRecordAsync(string recordName)
        {
            try
            {
                var cleanName = recordName.TrimEnd('.');
                _logger.LogDebug("[RFC2136] Deleting TXT record: {RecordName}", cleanName);

                var serverAddress = await ResolveServerAddressAsync();
                var msg = new DnsUpdateMessage { ZoneName = DomainName.Parse(_zoneName) };

                var domainName = DomainName.Parse(cleanName);
                msg.Updates.Add(new DeleteAllRecordsUpdate(domainName, RecordType.Txt));

                msg.TSigOptions = new TSigRecord(
                    DomainName.Parse(_tsigKeyName),
                    _tsigAlgorithm,
                    DateTime.Now,
                    new TimeSpan(0, 5, 0),
                    msg.TransactionID,
                    ReturnCode.NoError,
                    null,
                    _tsigKey);

                var client = new ArDnsClient(serverAddress, _serverPort);
                var response = await client.SendUpdateAsync(msg);

                // No response, NOERROR, or NXDOMAIN all mean there is nothing left to
                // clean up (or the delete succeeded) — treat as an idempotent success.
                if (response == null || response.ReturnCode == ReturnCode.NoError || response.ReturnCode == ReturnCode.NxDomain)
                {
                    _logger.LogInformation("[RFC2136] Successfully deleted TXT record: {RecordName}", cleanName);
                    return true;
                }

                // Any other rcode (REFUSED, NOTAUTH, SERVFAIL, ...) is a real failure that
                // previously returned false and was silently swallowed by the AnyGateway
                // service. Surface it in both the log and the enrollment error.
                _logger.LogError(
                    "[RFC2136] Failed to delete TXT record '{RecordName}' in zone '{Zone}' on {Server}:{Port}. Return code: {ReturnCode}.",
                    cleanName, _zoneName, _serverHost, _serverPort, response.ReturnCode);
                throw new InvalidOperationException(
                    $"RFC2136 DNS update to delete TXT record '{cleanName}' in zone '{_zoneName}' on {_serverHost}:{_serverPort} failed with return code '{response.ReturnCode}'. " +
                    "A REFUSED/NOTAUTH code usually indicates a TSIG key/zone mismatch or the server not being authoritative for the zone.");
            }
            catch (InvalidOperationException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[RFC2136] Error deleting TXT record for {RecordName} in zone '{Zone}' on {Server}:{Port}", recordName, _zoneName, _serverHost, _serverPort);
                throw new InvalidOperationException(
                    $"RFC2136 DNS provider error deleting TXT record '{recordName}' in zone '{_zoneName}' on {_serverHost}:{_serverPort}: {ex.Message}", ex);
            }
        }

        private async Task<IPAddress> ResolveServerAddressAsync()
        {
            if (IPAddress.TryParse(_serverHost, out var address))
            {
                return address;
            }

            var addresses = await Dns.GetHostAddressesAsync(_serverHost);
            if (addresses.Length == 0)
            {
                _logger.LogError(
                    "[RFC2136] Could not resolve DNS server host '{Server}'. Verify the Rfc2136_Server value is a reachable hostname or IP address.",
                    _serverHost);
                throw new InvalidOperationException(
                    $"Could not resolve RFC2136 DNS server host '{_serverHost}'. Verify the Rfc2136_Server value is a reachable hostname or IP address.");
            }

            return addresses.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                ?? addresses[0];
        }

        private static TSigAlgorithm ParseTsigAlgorithm(string algorithm)
        {
            var normalizedAlgorithm = algorithm?.ToLowerInvariant()?.Trim()?.Replace("-", "") ?? "hmacsha256";

            if (Enum.TryParse<TSigAlgorithm>(normalizedAlgorithm, true, out var result))
            {
                return result;
            }

            return normalizedAlgorithm switch
            {
                "hmacmd5" => TSigAlgorithm.Md5,
                "hmacsha1" => TSigAlgorithm.Sha1,
                "hmacsha256" => TSigAlgorithm.Sha256,
                "hmacsha384" => TSigAlgorithm.Sha384,
                "hmacsha512" => TSigAlgorithm.Sha512,
                "sha256" => TSigAlgorithm.Sha256,
                "sha384" => TSigAlgorithm.Sha384,
                "sha512" => TSigAlgorithm.Sha512,
                _ => TSigAlgorithm.Sha256
            };
        }
    }
}
