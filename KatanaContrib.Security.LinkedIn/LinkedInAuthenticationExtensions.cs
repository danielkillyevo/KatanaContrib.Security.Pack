using System;
using Owin;

namespace KatanaContrib.Security.LinkedIn
{    
    public static class LinkedInAuthenticationExtensions
    {       
        public static IAppBuilder UseLinkedInAuthentication(this IAppBuilder app, LinkedInAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(LinkedInAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseLinkedInAuthentication(
            this IAppBuilder app,
            string apiKey,
            string secretKey)
        {
            return UseLinkedInAuthentication(
                app,
                new LinkedInAuthenticationOptions
                {
                    AppId = apiKey,
                    AppSecret = secretKey
                });
        }
    }
}
