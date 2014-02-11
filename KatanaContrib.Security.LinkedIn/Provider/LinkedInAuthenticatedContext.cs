using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace KatanaContrib.Security.LinkedIn.Provider
{
    public class LinkedInAuthenticatedContext : BaseContext
    {
        public LinkedInAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;         

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            FirstName = TryGetValue(user, "first-name");
            LastName = TryGetValue(user, "last-name");
            UserName = TryGetValue(user, "formatted-name");
            Id = TryGetValue(user, "id");
            Url = TryGetValue(user, "public-profile-url");
            Email = TryGetValue(user, "email-address");

        }

        public JObject User { get; private set; }
        public string AccessToken { get; private set; }
        public TimeSpan? ExpiresIn { get; set; }
        public string Id { get; private set; }
        public string FirstName { get; private set; }
        public string LastName { get; private set; }
        public string Url { get; private set; }
        public string UserName { get; private set; }
        public string Email { get; private set; }
        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }
        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
