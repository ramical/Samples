using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using JWT2SAML.Models;

public class OnBehalfOfTokenRequest
{
    public string grant_type { get; set; }
    public string assertion { get; set; }
    public string client_id { get; set; }
    public string client_secret { get; set; }
    public string resource { get; set; }
    public string requested_token_use { get; set; }
    public string requested_token_type { get; set; }
}


public class OnBehalfOfTokenResponse
{
    [JsonProperty("access_token")]
    public string AccessToken { get; set; }

    [JsonProperty("expires_in")]
    public string ExpiresIn { get; set; }

    [JsonProperty("expires_on")]
    public string ExpiresOn { get; set; }

    [JsonProperty("ext_expires_in")]
    public string ExtExpiresIn { get; set; }

    [JsonProperty("issued_token_type")]
    public string IssuedTokenType { get; set; }

    [JsonProperty("refresh_token")]
    public string RefreshToken { get; set; }

    [JsonProperty("resource")]
    public string Resource { get; set; }

    [JsonProperty("token_type")]
    public string TokenType{ get; set; }
}

namespace JWT2SAML.Controllers
{
    [Authorize]
    public class JWT2SAMLTransitionController : ApiController
    {
        // GET: JWT2SAMLTransition
        public async Task<JWT2SAMLTransition> Get()
        {
            BootstrapContext bootstrapContext = ClaimsPrincipal.Current.Identities.First().BootstrapContext as BootstrapContext;
            string accessToken = bootstrapContext.Token;

            using (HttpClient azureADTokenClient = new HttpClient())
            {
                string azureADTokenEndpoint = string.Format("https://login.microsoftonline.com/{0}/oauth2/token", ConfigurationManager.AppSettings["ida:Tenant"]);
                HttpResponseMessage response = await azureADTokenClient.PostAsync(azureADTokenEndpoint,
                    new FormUrlEncodedContent( new Dictionary<string,string>
                    {
                        {"grant_type","urn:ietf:params:oauth:grant-type:jwt-bearer" },
                        {"assertion",accessToken },// #access token is scoped to api manager service
                        {"client_id",ConfigurationManager.AppSettings["ida:Audience"] },// #api manager service
                        {"client_secret", ConfigurationManager.AppSettings["ida:ClientSecret"] },// #api manager client secret
                        {"resource", ConfigurationManager.AppSettings["ida:BackEndAPIResource"] },// #Backend api -- SAML App Entity ID
                        {"requested_token_use","on_behalf_of" },
                        {"requested_token_type", "urn:ietf:params:oauth:token-type:saml2" }
                    }
                    ));

                string responseContentString = await response.Content.ReadAsStringAsync();
                OnBehalfOfTokenResponse tokenResponse = JsonConvert.DeserializeObject<OnBehalfOfTokenResponse>(responseContentString);

                JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();
                string decodedJwt= jwtHandler.ReadToken(accessToken).ToString();

                string encodedSamlToken = tokenResponse.AccessToken;

                //Adjust format in the SAML token, which comes as JSON Base64
                //Learn more: https://jb64.org/specification/
                string adjustedFormat = encodedSamlToken.Replace("_", "/").Replace("-", "+");
                adjustedFormat = adjustedFormat.PadRight(adjustedFormat.Length + (4 - adjustedFormat.Length % 4) % 4, '=');
                string decodedSamlToken = Encoding.UTF8.GetString(Convert.FromBase64String(adjustedFormat));
                
                //NOTE: for this example, we are returning the SAML token for debugging/demo purposes.
                //The actual scenario in production should be to have the frontend interacting with the backend 
                //via Service-To-Service (S2S).
                return new JWT2SAMLTransition
                {
                    JWT = accessToken,
                    SAMLToken = encodedSamlToken,
                    DecodedSAMLToken = decodedSamlToken
                };
            }
        }
    }
}