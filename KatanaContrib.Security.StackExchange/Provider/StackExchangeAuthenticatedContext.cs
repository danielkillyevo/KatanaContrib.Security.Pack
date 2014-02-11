using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace KatanaContrib.Security.StackExchange
{
    public class StackExchangeAuthenticatedContext : BaseContext
    {
        public StackExchangeAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            AccountId = TryGetValue(user, "account_id");
            DisplayName = TryGetValue(user, "display_name");
            Link = TryGetValue(user, "link");
            UserId = TryGetValue(user, "user_id");
            Email = TryGetValue(user, "email");
        }
       
        public JObject User { get; private set; }        
        public string AccessToken { get; private set; }        
        public TimeSpan? ExpiresIn { get; set; }        
        public string AccountId { get; private set; }        
        public string DisplayName { get; private set; }
        public string Link { get; private set; }        
        public string UserId { get; private set; }      
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
