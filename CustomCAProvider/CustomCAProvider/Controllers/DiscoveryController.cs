using Microsoft.AzureADSamples.CustomCAProvider.Properties;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json;
using System.Net.Http;
using System.Text;
using System.Web.Http;

namespace Microsoft.AzureADSamples.CustomCAProvider.Controllers
{
    public class DiscoveryController : ApiController
    {
        public HttpResponseMessage Get()
        {
            OpenIdConnectConfiguration oidcConfiguration = new OpenIdConnectConfiguration();
            oidcConfiguration.Issuer = Settings.Default.ExtensionClaimsIssuer;
            oidcConfiguration.AuthorizationEndpoint = string.Format(
                "https://{0}/api/Authorize", Settings.Default.ExtensionEndpointHostName);
            oidcConfiguration.JwksUri = string.Format("http://{0}/.well-known/jwks",
                Settings.Default.ExtensionEndpointHostName);
            oidcConfiguration.GrantTypesSupported.Add("implicit");
            oidcConfiguration.ResponseTypesSupported.Add("id_token");
            oidcConfiguration.ResponseModesSupported.Add("form_post");
            oidcConfiguration.ScopesSupported.Add("openid");
            oidcConfiguration.IdTokenSigningAlgValuesSupported.Add("RS256");
            oidcConfiguration.SubjectTypesSupported.Add("public");

            foreach (string supportedClaim in Settings.Default.SupportedExtensionClaims)
            {
                oidcConfiguration.ClaimsSupported.Add(supportedClaim);
            }

            return new HttpResponseMessage()
            {
                Content = new StringContent(
                    JsonConvert.SerializeObject(oidcConfiguration, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore } ),
                    Encoding.UTF8,
                    "application/json")
            };
        }
    }
}