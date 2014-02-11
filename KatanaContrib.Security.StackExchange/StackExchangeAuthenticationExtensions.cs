using System;
using Owin;

namespace KatanaContrib.Security.StackExchange
{
    public static class StackExchangeAuthenticationExtensions
    {
        public static IAppBuilder UseStackExchangeAuthentication(this IAppBuilder app, StackExchangeAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(StackExchangeAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseStackExchangeAuthentication(
            this IAppBuilder app,
            string appId,
            string appSecret,
            string site,
            string key)
        {
            return UseStackExchangeAuthentication(
                app,
                new StackExchangeAuthenticationOptions
                {
                    ClientId = appId,
                    ClientSecret = appSecret,
                    Site = site,
                    Key = key,
                });
        }
    }
}
