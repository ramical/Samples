using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace JWT2SAML.Models
{
    public class JWT2SAMLTransition
    {
        public string JWT { get; set; }
        public string SAMLToken { get; set; }
        public string DecodedSAMLToken { get; set; }

    }
}