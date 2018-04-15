using Microsoft.Owin.Security.ActiveDirectory;
using Owin;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;

namespace JWT2SAML
{
    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app) {

            app.UseWindowsAzureActiveDirectoryBearerAuthentication(
                new WindowsAzureActiveDirectoryBearerAuthenticationOptions
                {
                    Tenant = ConfigurationManager.AppSettings["ida:Tenant"],
                    TokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters
                    {
                        SaveSigninToken = true,
                        ValidAudience = ConfigurationManager.AppSettings["ida:Audience"],
                    }
                });
        }
    }
}