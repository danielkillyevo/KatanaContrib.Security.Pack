using System;
using System.Globalization;
using System.Security.Claims;
using System.Xml;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace KatanaContrib.Security.VK
{
    public class VkAuthenticatedContext : BaseContext
    {
        public VkAuthenticatedContext(IOwinContext context, XmlDocument userxml, string accessToken, string expires)
            : base(context)
        {
            UserXml = userxml;
            AccessToken = accessToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue("uid");
            Name = TryGetValue("first_name");
            LastName = TryGetValue("last_name");
            UserName = TryGetValue("screen_name");
            Nickname = TryGetValue("nickname");
            Link = TryGetValue("photo_50");
        }

        public XmlDocument UserXml { get; private set; }
        public string AccessToken { get; private set; }
        public TimeSpan? ExpiresIn { get; set; }
        public string Id { get; private set; }
        public string Name { get; private set; }
        public string LastName { get; private set; }

        public string FullName
        {
            get { return Name + " " + LastName; }
        }

        public string DefaultName
        {
            get
            {
                if (!String.IsNullOrEmpty(UserName))
                    return UserName;

                if (!String.IsNullOrEmpty(Nickname))
                    return Nickname;

                return FullName;
            }
        }

        public string Link { get; private set; }
        public string UserName { get; private set; }
        public string Nickname { get; private set; }
        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }

        private string TryGetValue(string propertyName)
        {
            XmlNodeList elemList = UserXml.GetElementsByTagName(propertyName);
            if (elemList != null)
            {
                if (elemList[0] != null)
                    return elemList[0].InnerText.Trim();
            }

            return String.Empty;
        }
    }
}