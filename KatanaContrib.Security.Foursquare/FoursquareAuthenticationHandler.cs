using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace KatanaContrib.Security.Foursquare
{
    internal class FoursquareAuthenticationHandler : AuthenticationHandler<FoursquareAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "https://foursquare.com/oauth2/access_token";
        private const string ApiEndpoint = "https://api.foursquare.com/v2/users/self";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public FoursquareAuthenticationHandler(HttpClient httpClient, ILogger logger)
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
               
                state = Request.Cookies["state_value"];

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

                string tokenRequest = "grant_type=authorization_code" +
                    "&code=" + Uri.EscapeDataString(code) +
                    "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                    "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                    "&client_secret=" + Uri.EscapeDataString(Options.ClientSecret);

                HttpResponseMessage tokenResponse = await _httpClient.GetAsync(TokenEndpoint + "?" + tokenRequest, Request.CallCancelled);
                tokenResponse.EnsureSuccessStatusCode();
                string text = await tokenResponse.Content.ReadAsStringAsync();
                JObject form = JObject.Parse(text);

                JToken accessToken = null;

                foreach(var x in form)
                {
                    if(x.Key == "access_token")
                    {
                        accessToken = x.Value;
                    }
                }

                string expires = "5183999";

                HttpResponseMessage graphResponse = await _httpClient.GetAsync(
                    ApiEndpoint + "?oauth_token=" + Uri.EscapeDataString(accessToken.ToString()) + "&v=20131201", Request.CallCancelled);
                graphResponse.EnsureSuccessStatusCode();
                text = await graphResponse.Content.ReadAsStringAsync();
                JObject result = JObject.Parse(text);

                JToken response = result["response"];
                JObject user = response["user"] as JObject;

                var context = new FoursquareAuthenticatedContext(Context, user, accessToken.ToString(), expires);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.LastName) && !string.IsNullOrEmpty(context.FirstName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, string.Format("{0} {1}", context.FirstName,context.LastName), XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.FirstName))
                {
                    context.Identity.AddClaim(new Claim("urn:foursquare:name", context.FirstName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Url))
                {
                    context.Identity.AddClaim(new Claim("urn:foursquare:url", context.Url, XmlSchemaString, Options.AuthenticationType));
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

                string state = Options.StateDataFormat.Protect(properties);
                
                Response.Cookies.Append("state_value", state, new CookieOptions(){Expires = DateTime.Now.AddDays(14)});

                string authorizationEndpoint = "https://foursquare.com/oauth2/authenticate" +
                        "?client_id=" + Uri.EscapeDataString(Options.ClientId) +
                        "&response_type=code" +                        
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri);

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

                var context = new FoursquareReturnEndpointContext(Context, ticket);
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
