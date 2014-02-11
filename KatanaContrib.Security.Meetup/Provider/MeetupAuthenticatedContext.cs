using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace KatanaContrib.Security.Meetup
{
    public class MeetupAuthenticatedContext : BaseContext
    {
        public MeetupAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue(user, "id");
            Name = TryGetValue(user, "name");
            Link = TryGetValue(user, "link");
            City = TryGetValue(user, "city");
            Country = TryGetValue(user, "country");
            Joined = TryGetValue(user, "joined");
            PhotoUrl = TryGetValue(user, "photo_url");

        }

        public JObject User { get; private set; }

        public string AccessToken { get; private set; }

        public TimeSpan? ExpiresIn { get; set; }

        public string Id { get; private set; }

        public string Name { get; private set; }

        public string Link { get; private set; }

        public string City { get; private set; }

        public string Country { get; private set; }

        public string Joined { get; private set; }

        public string PhotoUrl { get; private set; }

        public ClaimsIdentity Identity { get; set; }

        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
