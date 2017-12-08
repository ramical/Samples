namespace Microsoft.AzureADSamples.CustomCAProvider.Models
{
    public class AuthorizeModel
    {
        public string Scope { get; set; }

        public string Response_Mode { get; set; }

        public string Id_Token_Hint { get; set; }

        public string Response_Type { get; set; }

        public string Client_Id { get; set; }

        public string Redirect_Uri { get; set; }

        public string Claims { get; set; }

        public string Nonce { get; set; }

        public string State { get; set; }
    }
}