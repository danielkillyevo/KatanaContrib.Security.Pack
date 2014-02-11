using System;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace KatanaContrib.Security.Foursquare
{
    public class FoursquareAuthenticationOptions : AuthenticationOptions
    {
        public FoursquareAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-foursquare");
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        public TimeSpan BackchannelTimeout { get; set; }

        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        public PathString CallbackPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public IFoursquareAuthenticationProvider Provider { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

    }
}
