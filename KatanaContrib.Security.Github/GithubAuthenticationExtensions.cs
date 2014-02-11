using System;
using Owin;

namespace KatanaContrib.Security.Github
{
    public static class GithubAuthenticationExtensions
    {
        public static IAppBuilder UseGithubAuthentication(this IAppBuilder app, GithubAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(GithubAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseGithubAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientSecret)
        {
            return UseGithubAuthentication(
                app,
                new GithubAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                });
        }
    }
}
