using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace KatanaContrib.Security.Instagram
{
    public class InstagramAuthenticatedContext : BaseContext
    {
        public InstagramAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
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
            FullName = TryGetValue(user, "full_name");
            ProfilePicture = TryGetValue(user, "profile_picture");
            UserName = TryGetValue(user, "username");
            //Email = TryGetValue(user, "email");
        }
        public JObject User { get; private set; }
        public string AccessToken { get; private set; }
        public TimeSpan? ExpiresIn { get; set; }
        public string Id { get; private set; }
        public string FullName { get; private set; }
        public string ProfilePicture { get; private set; }
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
