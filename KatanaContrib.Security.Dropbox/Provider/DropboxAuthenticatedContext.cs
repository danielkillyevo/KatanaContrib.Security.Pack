using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace KatanaContrib.Security.Dropbox
{
    public class DropboxAuthenticatedContext : BaseContext
    {
        public DropboxAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            UId = TryGetValue(user, "uid");
            DisplayName = TryGetValue(user, "display_name");
            ReferralLink = TryGetValue(user, "referral_link");
            Country = TryGetValue(user, "country");
            Email = TryGetValue(user, "email");
        }
        public JObject User { get; private set; }
        public string AccessToken { get; private set; }
        public TimeSpan? ExpiresIn { get; set; }
        public string UId { get; private set; }
        public string DisplayName { get; private set; }
        public string ReferralLink { get; private set; }
        public string Country { get; private set; }
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
