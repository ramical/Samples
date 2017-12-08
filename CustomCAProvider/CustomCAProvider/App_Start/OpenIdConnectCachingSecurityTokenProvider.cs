using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Security.Jwt;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AzureADSamples.CustomCAProvider.App_Start
{
    // This class is necessary because the OAuthBearer Middleware does not leverage
    // the OpenID Connect metadata endpoint exposed by the STS by default.
    // Taken from https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet
    public class OpenIdConnectCachingSecurityTokenProvider : IIssuerSecurityTokenProvider
    {
        public ConfigurationManager<OpenIdConnectConfiguration> _configManager;
        private string _issuer;
        private readonly string _metadataEndpoint;

        private readonly ReaderWriterLockSlim _synclock = new ReaderWriterLockSlim();

        private IEnumerable<Microsoft.IdentityModel.Tokens.SecurityKey> _securityKeys;

        public OpenIdConnectCachingSecurityTokenProvider(string metadataEndpoint)
        {
            _metadataEndpoint = metadataEndpoint;
            _configManager = new ConfigurationManager<OpenIdConnectConfiguration>(metadataEndpoint, new OpenIdConnectConfigurationRetriever());

            RetrieveMetadata();
        }

        /// <summary>
        /// Gets the issuer the credentials are for.
        /// </summary>
        /// <value>
        /// The issuer the credentials are for.
        /// </value>
        public string Issuer
        {
            get
            {
                _synclock.EnterReadLock();
                try
                {
                    return _issuer;
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        /// <summary>
        /// Gets all known security tokens.
        /// </summary>
        /// <value>
        /// All known security tokens.
        /// </value>
        public IEnumerable<System.IdentityModel.Tokens.SecurityToken> SecurityTokens
        {
            get
            {
                return null;
            }
        }

        public IEnumerable<Microsoft.IdentityModel.Tokens.SecurityKey> SecurityKeys
        {
            get
            {
                _synclock.EnterReadLock();
                try
                {
                    return _securityKeys;
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        private void RetrieveMetadata()
        {
            _synclock.EnterWriteLock();
            try
            {
                OpenIdConnectConfiguration config = Task.Run(_configManager.GetConfigurationAsync).Result;
                _issuer = config.Issuer;
                _securityKeys = config.SigningKeys;
            }
            finally
            {
                _synclock.ExitWriteLock();
            }
        }
    }
}