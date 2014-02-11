using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace KatanaContrib.Security.Meetup
{
    public class MeetupAuthenticationOptions : AuthenticationOptions
    {
        public MeetupAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-meetup");
            AuthenticationMode = AuthenticationMode.Passive;

            //added scope 'ageless' to increase the expiry time 
            // of the oauth tokens upto 2 weeks
            Scope = new List<string>() { "ageless" };
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }
        public string Key { get; set; }
        public string Secret { get; set; }
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
        public IMeetupAuthenticationProvider Provider { get; set; }
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        public IList<string> Scope { get; private set; }
    }
}
