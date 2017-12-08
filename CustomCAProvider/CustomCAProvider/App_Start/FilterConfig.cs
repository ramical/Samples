using System.Web.Mvc;

namespace Microsoft.AzureADSamples.CustomCAProvider
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
            filters.Add(new RequireHttpsAttribute());
            filters.Add(new System.Web.Mvc.AuthorizeAttribute());
        }
    }
}
