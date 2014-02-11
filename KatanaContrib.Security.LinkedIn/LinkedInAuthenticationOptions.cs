using System;
using System.Collections.Generic;
using System.Net.Http;
using KatanaContrib.Security.LinkedIn.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace KatanaContrib.Security.LinkedIn
{
    public class LinkedInAuthenticationOptions : AuthenticationOptions
    {
        public LinkedInAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-linkedin");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>();
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }
        public string AppId { get; set; }
        public string AppSecret { get; set; }


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
        public ILinkedInAuthenticationProvider Provider { get; set; }
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        public IList<string> Scope { get; set; }
    }
}
