using System;
using System.Collections.Generic;
using Owin;

namespace KatanaContrib.Security.MyMail
{
    public static class MyMailAuthenticationExtensions
    {
        public static IAppBuilder UseMyMailAuthentication(this IAppBuilder app, MyMailAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof (MyMailAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseMyMailAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientSecret)
        {
            return UseMyMailAuthentication(
                app,
                new MyMailAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret
                });
        }

        public static IAppBuilder UseMyMailAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientSecret,
            IList<string> scope)
        {
            return UseMyMailAuthentication(
                app,
                new MyMailAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                    Scope = scope
                });
        }
    }
}