using Microsoft.AzureADSamples.CustomCAProvider.Properties;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Http;

namespace Microsoft.AzureADSamples.CustomCAProvider.Controllers
{
    public class JwksController : ApiController
    {
        private static Dictionary<string, object> DescribeCert(X509Certificate2 certificate)
        {
            Dictionary<string, object> key = new Dictionary<string, object>();

            string certificateBody = Convert.ToBase64String(certificate.GetRawCertData());
            string thumbprint = Base64UrlEncoder.Encode(certificate.GetCertHash());

            RSAParameters publicKeyParameters = ((RSACryptoServiceProvider)certificate.PublicKey.Key).ExportParameters(false);
            string publicKeyModulus = Base64UrlEncoder.Encode(publicKeyParameters.Modulus);
            string publicKeyExponent = Convert.ToBase64String(publicKeyParameters.Exponent);

            key["kty"] = "RSA";
            key["use"] = "sig";
            key["kid"] = thumbprint;
            key["x5t"] = thumbprint;
            key["n"] = publicKeyModulus;
            key["e"] = publicKeyExponent;
            key["x5c"] = new List<object> { certificateBody };

            return key;
        }

        public HttpResponseMessage Get()
        {
            Dictionary<string, object> jwks = new Dictionary<string, object>();

            string certWithPrivateKeyString = ConfigurationManager.AppSettings["ExtensionClaimsSigningCertificateString"];
            X509Certificate2 signingCert = new X509Certificate2(
                Convert.FromBase64String(certWithPrivateKeyString),
                (string)null,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            jwks["keys"] = new List<Dictionary<string, object>> { DescribeCert(signingCert) };

            return new HttpResponseMessage()
            {
                Content = new StringContent(
                    JsonConvert.SerializeObject(jwks, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore }),
                    Encoding.UTF8,
                    "application/json")
            };
        }
    }
}