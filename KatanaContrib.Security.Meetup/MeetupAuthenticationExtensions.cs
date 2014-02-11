using System;
using Owin;

namespace KatanaContrib.Security.Meetup
{
    public static class MeetupAuthenticationExtensions
    {
        public static IAppBuilder UseMeetupAuthentication(this IAppBuilder app, MeetupAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(MeetupAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseMeetupAuthentication(
            this IAppBuilder app,
            string key,
            string secret)
        {
            return UseMeetupAuthentication(
                app,
                new MeetupAuthenticationOptions
                {
                    Key = key,
                    Secret = secret,
                });
        }
    }
}
