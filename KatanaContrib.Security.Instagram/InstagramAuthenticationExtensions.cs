using System;
using Owin;

namespace KatanaContrib.Security.Instagram
{
    public static class InstagramAuthenticationExtensions
    {
        public static IAppBuilder UseInstagramAuthentication(this IAppBuilder app, InstagramAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(InstagramAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseInstagramAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientSecret)
        {
            return UseInstagramAuthentication(
                app,
                new InstagramAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                });
        }
    }
}
