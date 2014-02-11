using System;
using System.Globalization;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace KatanaContrib.Security.Github
{   
    public class GithubAuthenticationMiddleware : AuthenticationMiddleware<GithubAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public GithubAuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
             GithubAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ClientId))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "The '{0}' option must be provided.", "AppId"));
            }
            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "The '{0}' option must be provided.", "AppSecret"));
            }
            if (!Options.Scope.Contains(Constants.DefaultScope))
            {
                Options.Scope.Add(Constants.DefaultScope);
            }

            _logger = app.CreateLogger<GithubAuthenticationMiddleware>();

            if (Options.Provider == null)
            {
                Options.Provider = new GithubAuthenticationProvider();
            }
            if (Options.StateDataFormat == null)
            {
                IDataProtector dataProtector = app.CreateDataProtector(
                    typeof(GithubAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options));
            _httpClient.Timeout = Options.BackchannelTimeout;
            _httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
        }

        protected override AuthenticationHandler<GithubAuthenticationOptions> CreateHandler()
        {
            return new GithubAuthenticationHandler(_httpClient, _logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(GithubAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            if (options.BackchannelCertificateValidator != null)
            {
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("An ICertificateValidator cannot be specified at the same time as an HttpMessageHandler unless it is a WebRequestHandler.");
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }
    }
}
