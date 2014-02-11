using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace KatanaContrib.Security.Foursquare
{
    public class FoursquareAuthenticatedContext : BaseContext
    {
        public FoursquareAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
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
            FirstName = TryGetValue(user, "firstName");
            Url = TryGetValue(user, "url");
            LastName = TryGetValue(user, "lastName");
            Email =  ((dynamic)user).contact.email ?? "";
        }

        public JObject User { get; private set; }

        public string AccessToken { get; private set; }

        public TimeSpan? ExpiresIn { get; set; }

        public string Id { get; private set; }

        public string FirstName { get; private set; }

        public string Url { get; private set; }

        public string LastName { get; private set; }

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
