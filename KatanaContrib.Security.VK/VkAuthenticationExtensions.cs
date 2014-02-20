using System;
using Owin;
using System.Collections.Generic;

namespace KatanaContrib.Security.VK
{
    public static class VkAuthenticationExtensions
    {
        public static IAppBuilder UseVkontakteAuthentication(this IAppBuilder app, VkAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(VkAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseVkontakteAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientSecret)
        {
            return UseVkontakteAuthentication(
                app,
                new VkAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret
                });
        }

        public static IAppBuilder UseVkontakteAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientSecret,
            IList<string> scope)
        {
            return UseVkontakteAuthentication(
                app,
                new VkAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                    Scope = scope
                });
        }
    }
}
