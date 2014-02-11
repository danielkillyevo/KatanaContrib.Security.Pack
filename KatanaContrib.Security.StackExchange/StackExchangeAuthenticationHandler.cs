using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Helpers;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace KatanaContrib.Security.StackExchange
{
    internal class StackExchangeAuthenticationHandler : AuthenticationHandler<StackExchangeAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "https://stackexchange.com/oauth/access_token";
        private const string ApiEndpoint = "https://api.stackexchange.com/2.1/me";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public StackExchangeAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                string tokenRequest = "client_id=" + Uri.EscapeDataString(Options.ClientId) +
                    "&client_secret=" + Uri.EscapeDataString(Options.ClientSecret) +
                    "&code=" + Uri.EscapeDataString(code) +
                    "&redirect_uri=" + Uri.EscapeDataString(redirectUri);             
                    
                HttpRequestMessage _httpRequest = new HttpRequestMessage();
                HttpResponseMessage tokenResponse = await _httpClient.PostAsync(TokenEndpoint + "?" + tokenRequest, _httpRequest.Content, Request.CallCancelled);
                tokenResponse.EnsureSuccessStatusCode();
                string text = await tokenResponse.Content.ReadAsStringAsync();
                IFormCollection form = WebHelpers.ParseForm(text);

                string accessToken = form["access_token"];
                string expires = form["expires"];

                HttpResponseMessage graphResponse = await _httpClient.GetAsync(
                    ApiEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken) + 
                    "&site=" + Uri.EscapeDataString(Options.Site) +
                    "&key=" + Uri.EscapeDataString(Options.Key), Request.CallCancelled);
                graphResponse.EnsureSuccessStatusCode();

                
                Stream rawStream = await graphResponse.Content.ReadAsStreamAsync();

                using(GZipStream gzipStream = new GZipStream(rawStream,CompressionMode.Decompress))
                using(StreamReader streamReader = new StreamReader(gzipStream))
                {
                    text = await streamReader.ReadToEndAsync();
                }

                JObject info = JObject.Parse(text);
                JToken items = info["items"];
                JToken userToken = items.First;
                JObject user = userToken as JObject;

                var context = new StackExchangeAuthenticatedContext(Context, user, accessToken, expires);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
                if (!string.IsNullOrEmpty(context.UserId))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.UserId, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.DisplayName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.DisplayName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.AccountId))
                {
                    context.Identity.AddClaim(new Claim("urn:stackexchange:accountId", context.AccountId, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Link))
                {
                    context.Identity.AddClaim(new Claim("urn:stackexchange:link", context.Link, XmlSchemaString, Options.AuthenticationType));
                }
                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri = 
                    Request.Scheme + 
                    Uri.SchemeDelimiter + 
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri + 
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri + 
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // comma separated
                string scope = string.Join(",", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);

                string authorizationEndpoint =
                    "https://stackexchange.com/oauth" +
                        "?response_type=code" +
                        "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                        "&scope=" + Uri.EscapeDataString(scope) +
                        "&state=" + Uri.EscapeDataString(state);

                Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                // TODO: error responses

                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new StackExchangeReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }
    }
}
