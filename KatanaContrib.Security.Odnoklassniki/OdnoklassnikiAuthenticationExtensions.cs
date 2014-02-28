using System;
using Owin;
using System.Collections.Generic;

namespace KatanaContrib.Security.Odnoklassniki
{
    public static class OdnoklassnikiAuthenticationExtensions
    {
        public static IAppBuilder UseOdnoklassnikiAuthentication(this IAppBuilder app, OdnoklassnikiAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(OdnoklassnikiAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseOdnoklassnikiAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientPublic,
            string clientSecret)
        {
            return UseOdnoklassnikiAuthentication(
                app,
                new OdnoklassnikiAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientPublic = clientPublic,
                    ClientSecret = clientSecret
                });
        }
    }
}
