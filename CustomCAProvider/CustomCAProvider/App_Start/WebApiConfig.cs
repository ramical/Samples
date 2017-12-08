using System.Web.Http;

namespace Microsoft.AzureADSamples.CustomCAProvider
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "OpenIdConfiguration",
                routeTemplate: ".well-known/openid-config",
                defaults: new { controller = "Discovery" }
            );

            config.Routes.MapHttpRoute(
                name: "OpenIdJwks",
                routeTemplate: ".well-known/jwks",
                defaults: new { controller = "Jwks" }
            );

            config.Routes.MapHttpRoute(
                name: "Authorize",
                routeTemplate: "api/Authorize",
                defaults: new { controller = "Authorize" }
            );
        }
    }
}
