using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace KatanaContrib.Security.Instagram
{
    public class InstagramAuthenticationOptions : AuthenticationOptions
    {
        public InstagramAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-instagram");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>();
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
        public IInstagramAuthenticationProvider Provider { get; set; }
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        public IList<string> Scope { get; private set; }
    }
}
