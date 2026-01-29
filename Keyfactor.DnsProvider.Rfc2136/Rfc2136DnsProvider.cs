// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0
using System.Net;
using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using ARSoft.Tools.Net.Dns.DynamicUpdate;
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
        private readonly string _serverHost;
        private readonly int _serverPort;
        private readonly string _zoneName;
        private readonly string _tsigKeyName;
        private readonly byte[] _tsigKey;
        private readonly TSigAlgorithm _tsigAlgorithm;
        private readonly ILogger _logger;

        public Rfc2136DnsProvider(
            string serverHost,
            string zoneName,
            string tsigKeyName,
            string tsigKeyValue,
            string tsigAlgorithm = "hmac-sha256",
            int serverPort = 53,
            ILogger logger = null)
        {
            _serverHost = serverHost ?? throw new ArgumentNullException(nameof(serverHost));
            _zoneName = zoneName?.TrimEnd('.') ?? throw new ArgumentNullException(nameof(zoneName));
            _tsigKeyName = tsigKeyName ?? throw new ArgumentNullException(nameof(tsigKeyName));
            _tsigKey = Convert.FromBase64String(tsigKeyValue ?? throw new ArgumentNullException(nameof(tsigKeyValue)));
            _tsigAlgorithm = ParseTsigAlgorithm(tsigAlgorithm);
            _serverPort = serverPort;
            _logger = logger;
        }

        public async Task<bool> CreateRecordAsync(string recordName, string txtValue)
        {
            try
            {
                var cleanName = recordName.TrimEnd('.');
                _logger?.LogDebug("[RFC2136] Creating TXT record: {RecordName} = {TxtValue}", cleanName, txtValue);

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

                _logger?.LogDebug("[RFC2136] Sending update to {Server}:{Port}", serverAddress, _serverPort);
                var client = new ArDnsClient(serverAddress, _serverPort);
                var response = await client.SendUpdateAsync(msg);

                if (response == null)
                {
                    _logger?.LogError("[RFC2136] No response received from DNS server");
                    throw new InvalidOperationException("RFC2136 DNS update failed: No response from server");
                }

                if (response.ReturnCode == ReturnCode.NoError)
                {
                    _logger?.LogInformation("[RFC2136] Successfully created TXT record: {RecordName}", cleanName);
                    return true;
                }

                _logger?.LogError("[RFC2136] Failed to create TXT record. Return code: {ReturnCode}", response.ReturnCode);
                throw new InvalidOperationException($"RFC2136 DNS update failed with return code: {response.ReturnCode}");
            }
            catch (InvalidOperationException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[RFC2136] Error creating TXT record for {RecordName}", recordName);
                throw new InvalidOperationException($"RFC2136 DNS provider error: {ex.Message}", ex);
            }
        }

        public async Task<bool> DeleteRecordAsync(string recordName)
        {
            try
            {
                var cleanName = recordName.TrimEnd('.');
                _logger?.LogDebug("[RFC2136] Deleting TXT record: {RecordName}", cleanName);

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

                if (response == null || response.ReturnCode == ReturnCode.NoError || response.ReturnCode == ReturnCode.NxDomain)
                {
                    _logger?.LogInformation("[RFC2136] Successfully deleted TXT record: {RecordName}", cleanName);
                    return true;
                }

                _logger?.LogWarning("[RFC2136] Delete returned code: {ReturnCode}", response.ReturnCode);
                return false;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[RFC2136] Error deleting TXT record for {RecordName}", recordName);
                return false;
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
                throw new InvalidOperationException($"Could not resolve DNS server: {_serverHost}");
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
