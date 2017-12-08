using Microsoft.AzureADSamples.CustomCAProvider.App_Start;
using Microsoft.AzureADSamples.CustomCAProvider.Models;
using Microsoft.AzureADSamples.CustomCAProvider.Properties;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Web.Http;
using System.Web.UI;

namespace Microsoft.AzureADSamples.CustomCAProvider.Controllers
{
    public class AuthorizeController : ApiController
    {
        private const string AzureADMetadataUriFormat = "https://login.microsoftonline.com/{0}/.well-known/openid-configuration";

        public HttpResponseMessage Index(AuthorizeModel azureAdAuthorizeRequest)
        {
           
            try
            {
                //Input Syntax Validation
                if (azureAdAuthorizeRequest.Id_Token_Hint == null)
                {
                    throw new InvalidDataException("id_token_hint is required.");
                }

                if (azureAdAuthorizeRequest.Response_Type != "id_token")
                {
                    throw new InvalidDataException("Unsupported response type.");
                }

                if (azureAdAuthorizeRequest.Response_Mode != "form_post")
                {
                    throw new InvalidDataException("Unsupported response mode.");
                }

                string requestClientId = azureAdAuthorizeRequest.Client_Id;

                //Validate the client id of the request is allowed
                if (!Settings.Default.AllowedExtensionClientIds.Contains(requestClientId))
                {
                    throw new InvalidDataException("Unauthorized client.");
                }

                if (!Settings.Default.AzureADAllowedRedirectUris.Contains(azureAdAuthorizeRequest.Redirect_Uri))
                {
                    throw new InvalidDataException("Unauthorized redirect uri.");
                }
                //End of input Syntax Validation

                //Validate and parse the original id_token_hint. We need to extract the 'sub' claim and reply it back
                JwtSecurityToken idTokenHint = ValidateIdTokenHint(azureAdAuthorizeRequest.Id_Token_Hint);
                string originalSub = idTokenHint.Claims.First(c => c.Type == "sub").Value;

                //Analyze the claims requested by Azure AD into the provider
                //In this sample, we will simply echo back exactly what Azure AD Requested.
                //In real examples, the provider would execute some custom logic
                ClaimsRequestParameter requestedControlClaims = JsonConvert.DeserializeObject<ClaimsRequestParameter>(azureAdAuthorizeRequest.Claims);
                if (requestedControlClaims.IdToken == null)
                {
                    throw new InvalidDataException("Unsupported claims request parameter.");
                }

                //In addition to the Sub is required to be returned
                requestedControlClaims.IdToken.Add(
                    "sub", new ClaimsRequestParameter.ClaimProperties() { Value = originalSub }
                    );

                //We will prepare the output here right away. If user interaction is required, return the proper redirections
                //to views to challenge user. 
                NameValueCollection dataToSend = new NameValueCollection();
                dataToSend.Add("state", azureAdAuthorizeRequest.State);
                dataToSend.Add("id_token", GenerateOutputToken(requestedControlClaims, requestClientId));

                Uri redirectUri = new Uri(azureAdAuthorizeRequest.Redirect_Uri);
                string formPost = BuildFormPostWithDataToSend(dataToSend, redirectUri);

                var response = Request.CreateResponse(HttpStatusCode.OK);
                response.Content = new StringContent(formPost, Encoding.UTF8, "text/html");
                response.Headers.Location = redirectUri;
                return response;
            }
            catch (Exception e)
            {
                return new HttpResponseMessage()
                {
                    Content = new StringContent(
                    JsonConvert.SerializeObject(e, Formatting.Indented, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore }),
                    Encoding.UTF8,
                    "application/json")
                };
            }
        }

        private static string BuildFormPostWithDataToSend(NameValueCollection dataToSend, Uri redirectUri)
        {
            StringWriter stringWriter = new StringWriter();
            using (HtmlTextWriter writer = new HtmlTextWriter(stringWriter))
            {
                writer.RenderBeginTag(HtmlTextWriterTag.Html);
                writer.RenderBeginTag(HtmlTextWriterTag.Head);
                writer.RenderBeginTag(HtmlTextWriterTag.Title);
                writer.Write("Working...");
                writer.RenderEndTag();
                writer.RenderEndTag();

                writer.RenderBeginTag(HtmlTextWriterTag.Body);

                writer.AddAttribute("method", WebRequestMethods.Http.Post);
                writer.AddAttribute("name", "hiddenform");
                writer.AddAttribute("action", HttpUtility.HtmlAttributeEncode(redirectUri.OriginalString));
                writer.RenderBeginTag(HtmlTextWriterTag.Form);

                foreach (string key in dataToSend)
                {
                    writer.AddAttribute("type", "hidden");
                    writer.AddAttribute("name", key);
                    writer.AddAttribute("value", dataToSend[key]);
                    writer.RenderBeginTag(HtmlTextWriterTag.Input);
                    writer.RenderEndTag();
                }

                writer.RenderBeginTag(HtmlTextWriterTag.Noscript);
                writer.RenderBeginTag(HtmlTextWriterTag.P);
                writer.Write("Script is disabled. Click Submit to continue.");
                writer.RenderEndTag();
                writer.AddAttribute("submit", "Submit");
                writer.RenderBeginTag(HtmlTextWriterTag.Input);
                writer.RenderEndTag();
                writer.RenderEndTag();

                writer.AddAttribute("language", "javascript");
                writer.RenderBeginTag(HtmlTextWriterTag.Script);
                writer.Write("document.forms[0].submit();");
                writer.RenderEndTag();
                writer.RenderEndTag();
                writer.RenderEndTag();
            }

            return stringWriter.ToString();
        }

        private static JwtSecurityToken ValidateIdTokenHint(string idTokenHintString)
        {
            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken parsedIdTokenHint = jwtSecurityTokenHandler.ReadJwtToken(idTokenHintString);

            if (parsedIdTokenHint == null)
            {
                throw new InvalidDataException("IdToken is not JwtToken.");
            }

            if (parsedIdTokenHint.Claims == null || !parsedIdTokenHint.Claims.Any())
            {
                throw new Exception("Empty claims found in id token hint");
            }

            string tenantId = parsedIdTokenHint.Claims.First(c => c.Type == "tid").Value;
            if (string.IsNullOrWhiteSpace(tenantId))
            {
                throw new InvalidDataException("Missing tenantId claim.");
            }

            if (!Settings.Default.AllowedTenantIds.Contains(tenantId))
            {
                throw new InvalidDataException("Invalid tenant id.");
            }

            string azureADTenantMetadataUri = string.Format(AzureADMetadataUriFormat, tenantId);
            OpenIdConnectCachingSecurityTokenProvider oidcTokenProvider = new OpenIdConnectCachingSecurityTokenProvider(azureADTenantMetadataUri);
            if (!oidcTokenProvider.SecurityKeys.Any())
            {
                throw new Exception("Couldn't retrieve security keys from OIDC metadata endpoint.");
            }

            TokenValidationParameters validationParameters = new TokenValidationParameters();
            validationParameters.ValidAudience = Settings.Default.AzureADExtensionClientId;
            validationParameters.ValidIssuer = oidcTokenProvider.Issuer;
            validationParameters.ClockSkew = TimeSpan.FromMinutes(5);

            validationParameters.IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
            {
                return oidcTokenProvider.SecurityKeys.Where(k => k.KeyId == kid);
            };

            SecurityToken validatedSecurityToken;
            ClaimsPrincipal claimsPrincipal = jwtSecurityTokenHandler.ValidateToken(
                idTokenHintString,
                validationParameters,
                out validatedSecurityToken);

            JwtSecurityToken validatedIdTokenHint = validatedSecurityToken as JwtSecurityToken;

            if (validatedIdTokenHint == null)
            {
                throw new Exception("IdToken is not a JwtSecurityToken.");
            }

            return validatedIdTokenHint;
        }

        private string GenerateOutputToken(ClaimsRequestParameter claimsRequested, string requestClientId)
        {
            //This logic will re-issue the claims requested by Azure AD. 
            //Insert here the specific logic for your custom providers
            List<Claim> claims = new List<Claim>();
            foreach (var claimRequested in claimsRequested.IdToken)
            {
                string claimValue = claimRequested.Value.Value ?? claimRequested.Value.Values?.FirstOrDefault();
                claims.Add(new Claim(claimRequested.Key, claimValue));
            };

            //JWT audience must match the client id that was requested 
            string audience = requestClientId;  

            string issuer = Settings.Default.ExtensionClaimsIssuer;

            //TODO: Add the configuration setting in your Azure Subscription or web.config file
            string certWithPrivateKeyString = ConfigurationManager.AppSettings["ExtensionClaimsSigningCertificateString"];
            X509Certificate2 signingCert = new X509Certificate2(
                Convert.FromBase64String(certWithPrivateKeyString),
                (string)null,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            X509SecurityKey securityKey = new X509SecurityKey(signingCert)
            {
                KeyId = Base64UrlEncoder.Encode(signingCert.GetCertHash())
            };

            RSACryptoServiceProvider cryptoServiceProvider = (RSACryptoServiceProvider)signingCert.PrivateKey;
            SigningCredentials signingCredentials = new SigningCredentials(new RsaSecurityKey(cryptoServiceProvider), SecurityAlgorithms.RsaSha256);
            signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

            JwtSecurityToken jwtToken = new JwtSecurityToken
            (
                issuer: issuer,
                audience: audience,
                claims: claims,
                signingCredentials: signingCredentials,
                expires: DateTime.Now.AddDays(1)
            );

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            string tokenString = tokenHandler.WriteToken(jwtToken);
            return tokenString;
        }


    }
}