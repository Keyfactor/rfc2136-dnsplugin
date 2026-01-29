// Copyright 2025 Keyfactor
// Licensed under the Apache License, Version 2.0
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.DomainValidator.Rfc2136
{
    /// <summary>
    /// RFC2136 Dynamic DNS Update domain validator for ACME DNS-01 challenges
    /// </summary>
    public class Rfc2136DomainValidator : IDomainValidator
    {
        private static readonly ILogger _logger = LogHandler.GetClassLogger<Rfc2136DomainValidator>();
        private Rfc2136DnsProvider _provider;
        private Dictionary<string, object> _configuration;

        public Dictionary<string, PropertyConfigInfo> GetDomainValidatorAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>()
            {
                ["Rfc2136_Server"] = new PropertyConfigInfo()
                {
                    Comments = "RFC2136: DNS Server hostname or IP address (Required)",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Rfc2136_Port"] = new PropertyConfigInfo()
                {
                    Comments = "RFC2136: DNS Server port (Optional, default: 53)",
                    Hidden = false,
                    DefaultValue = "53",
                    Type = "String"
                },
                ["Rfc2136_Zone"] = new PropertyConfigInfo()
                {
                    Comments = "RFC2136: DNS Zone name (Required)",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Rfc2136_TsigKeyName"] = new PropertyConfigInfo()
                {
                    Comments = "RFC2136: TSIG key name (Required)",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["Rfc2136_TsigKey"] = new PropertyConfigInfo()
                {
                    Comments = "RFC2136: TSIG key value (Base64 encoded) (Required)",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "Secret"
                },
                ["Rfc2136_TsigAlgorithm"] = new PropertyConfigInfo()
                {
                    Comments = "RFC2136: TSIG algorithm (Optional, default: hmac-sha256)",
                    Hidden = false,
                    DefaultValue = "hmac-sha256",
                    Type = "String"
                }
            };
        }

        public string GetValidationType()
        {
            return "DNS";
        }

        public void Initialize(IDomainValidatorConfigProvider configProvider)
        {
            _configuration = configProvider.DomainValidationConfiguration;

            string server = GetConfigValue("Rfc2136_Server");
            string zone = GetConfigValue("Rfc2136_Zone");
            string tsigKeyName = GetConfigValue("Rfc2136_TsigKeyName");
            string tsigKey = GetConfigValue("Rfc2136_TsigKey");
            string tsigAlgorithm = GetConfigValue("Rfc2136_TsigAlgorithm", "hmac-sha256");
            int port = int.TryParse(GetConfigValue("Rfc2136_Port", "53"), out var p) ? p : 53;

            if (string.IsNullOrWhiteSpace(server))
                throw new ArgumentException("Rfc2136_Server is required");
            if (string.IsNullOrWhiteSpace(zone))
                throw new ArgumentException("Rfc2136_Zone is required");
            if (string.IsNullOrWhiteSpace(tsigKeyName))
                throw new ArgumentException("Rfc2136_TsigKeyName is required");
            if (string.IsNullOrWhiteSpace(tsigKey))
                throw new ArgumentException("Rfc2136_TsigKey is required");

            _provider = new Rfc2136DnsProvider(server, zone, tsigKeyName, tsigKey, tsigAlgorithm, port, _logger);
        }

        public async Task<DomainValidationResult> StageValidation(string key, string value, CancellationToken cancellationToken)
        {
            try
            {
                var success = await _provider.CreateRecordAsync(key, value);

                return new DomainValidationResult
                {
                    Success = success,
                    ErrorMessage = success ? null : $"Failed to create DNS TXT record for {key}"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[RFC2136] StageValidation exception");
                return new DomainValidationResult
                {
                    Success = false,
                    ErrorMessage = $"Failed to create TXT record: {ex.Message}"
                };
            }
        }

        public async Task<DomainValidationResult> CleanupValidation(string key, CancellationToken cancellationToken)
        {
            try
            {
                var success = await _provider.DeleteRecordAsync(key);

                return new DomainValidationResult
                {
                    Success = success,
                    ErrorMessage = success ? null : $"Failed to delete DNS TXT record for {key}"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[RFC2136] CleanupValidation exception");
                return new DomainValidationResult
                {
                    Success = false,
                    ErrorMessage = $"Failed to delete TXT record: {ex.Message}"
                };
            }
        }

        public async Task ValidateConfiguration(Dictionary<string, object> configuration)
        {
            _configuration = configuration;

            string server = GetConfigValue("Rfc2136_Server");
            string zone = GetConfigValue("Rfc2136_Zone");
            string tsigKeyName = GetConfigValue("Rfc2136_TsigKeyName");
            string tsigKey = GetConfigValue("Rfc2136_TsigKey");

            if (string.IsNullOrWhiteSpace(server))
                throw new ArgumentException("Rfc2136_Server is required");
            if (string.IsNullOrWhiteSpace(zone))
                throw new ArgumentException("Rfc2136_Zone is required");
            if (string.IsNullOrWhiteSpace(tsigKeyName))
                throw new ArgumentException("Rfc2136_TsigKeyName is required");
            if (string.IsNullOrWhiteSpace(tsigKey))
                throw new ArgumentException("Rfc2136_TsigKey is required");

            await Task.CompletedTask;
        }

        private string GetConfigValue(string key, string defaultValue = "")
        {
            if (_configuration != null && _configuration.TryGetValue(key, out var value))
            {
                return value?.ToString() ?? defaultValue;
            }
            return defaultValue;
        }
    }
}
