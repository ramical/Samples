using Newtonsoft.Json;
using System.Collections.Generic;

namespace Microsoft.AzureADSamples.CustomCAProvider.Models
{
    public class ClaimsRequestParameter
    {
        public class ClaimProperties
        {
            [JsonProperty("essential")]
            public bool IsEssential { get; set; }

            [JsonProperty("value")]
            public string Value { get; set; }

            [JsonProperty("values")]
            public IEnumerable<string> Values { get; set; }
        }

        [JsonProperty("id_token")]
        public Dictionary<string, ClaimProperties> IdToken { get; set; }
    }
}