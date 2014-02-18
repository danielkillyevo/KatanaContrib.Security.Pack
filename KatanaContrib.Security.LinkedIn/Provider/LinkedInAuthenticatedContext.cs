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
        private int _expiresValue;

        public LinkedInAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
            : base(context)
        {
            this.ValidateParams(context, user, accessToken, expires);
            User = user;
            AccessToken = accessToken;                      
            FirstName = TryGetValue(user, "first-name");
            LastName = TryGetValue(user, "last-name");
            UserName = TryGetValue(user, "formatted-name");
            Id = TryGetValue(user, "id");         
            Url = TryGetValue(user, "public-profile-url");
            Email = TryGetValue(user, "email-address");
            this.ValidateUser();
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

        private void ValidateParams(IOwinContext context, JObject user, string accessToken, string expires)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user", "user is null");
            }
            if (accessToken == null)
            {
                throw new ArgumentNullException("accessToken", "access token is null");
            }
            if (context == null)
            {
                throw new ArgumentNullException("context", "context is null");
            }
            if (expires == null)
            {
                throw new ArgumentNullException("expires", "expires parameter is null");
            }
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out _expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(_expiresValue);
            }
            else
            {
                throw new ArgumentOutOfRangeException("expires", "expires value should be a number");
            }
        }
        private void ValidateUser()
        {
            if (UserName == null)
            {
                throw new ArgumentOutOfRangeException("user", "user doesn't have username");
            }
            if (Id == null)
            {
                throw new ArgumentOutOfRangeException("user", "user doesn't have id");
            }
        }
    }
}
