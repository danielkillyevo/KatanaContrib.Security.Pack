using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace KatanaContrib.Security.MyMail
{
    public class MyMailAuthenticatedContext : BaseContext
    {
        public MyMailAuthenticatedContext(IOwinContext context, JObject userInfo, string accessToken, string expires)
            : base(context)
        {
            UserInfo = userInfo;
            AccessToken = accessToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = userInfo.Value<string>("uid");
            FirstName = userInfo.Value<string>("first_name");
            LastName = userInfo.Value<string>("last_name");
            UserName = userInfo.Value<string>("nick");
            Email = userInfo.Value<string>("email");
            Link = userInfo.Value<string>("link");
        }

        public string FullName
        {
            get { return string.Format("{0} {1}", FirstName, LastName); }
        }

        public string DefaultName
        {
            get { return !String.IsNullOrEmpty(UserName) ? UserName : FullName; }
        }

        public string Link { get; set; }
        public string Email { get; set; }
        public string UserName { get; set; }
        public string LastName { get; set; }
        public string FirstName { get; set; }
        public string Id { get; set; }

        public JObject UserInfo { get; set; }
        public string AccessToken { get; private set; }
        public TimeSpan? ExpiresIn { get; set; }
        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }
    }
}