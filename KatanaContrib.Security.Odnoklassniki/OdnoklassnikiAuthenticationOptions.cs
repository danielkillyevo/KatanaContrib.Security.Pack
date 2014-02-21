using System;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using System.Collections.Generic;

namespace KatanaContrib.Security.Odnoklassniki
{
    public class OdnoklassnikiAuthenticationOptions : AuthenticationOptions
    {
        public OdnoklassnikiAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-odnoklassniki");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>();
            Version = "5.3";
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }
        public string ClientId { get; set; }
        public string ClientPublic { get; set; }
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
        public IOdnoklassnikiAuthenticationProvider Provider { get; set; }
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        public string StoreState { get; set; }
        public IList<string> Scope { get; set; }
        public string Version { get; set; }
    }
}
