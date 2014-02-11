using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace KatanaContrib.Security.Dropbox
{
    internal class DropboxAuthenticationHandler : AuthenticationHandler<DropboxAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "https://api.dropbox.com/1/oauth2/token";
        private const string ApiEndpoint = "https://api.dropbox.com/1/account/info";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public DropboxAuthenticationHandler(HttpClient httpClient, ILogger logger)
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
                string csrf_state = null;

                //obtaining the shortened state value from the cookie
                HttpCookie csrfStateCookie = HttpContext.Current.Request.Cookies["csrf_state"];
                string originalStateString = csrfStateCookie.Value;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    csrf_state = values[0];
                }

                //verify sent and recieved state parameters for CSRF
                if(csrf_state != originalStateString)
                {
                    return null;
                }

                //Obtain the original state value from cookie
                HttpCookie stateCookie = HttpContext.Current.Request.Cookies["state"];
                string state = stateCookie.Value;

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                string tokenRequest = "grant_type=authorization_code" +
                    "&code=" + Uri.EscapeDataString(code) +
                    "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                    "&client_id=" + Uri.EscapeDataString(Options.AppKey) +
                    "&client_secret=" + Uri.EscapeDataString(Options.AppSecret);

                HttpRequestMessage request = new HttpRequestMessage();
                HttpResponseMessage tokenResponse = await _httpClient.PostAsync(TokenEndpoint + "?" + tokenRequest, request.Content, Request.CallCancelled);
                tokenResponse.EnsureSuccessStatusCode();
                string text = await tokenResponse.Content.ReadAsStringAsync();

                JObject tokenResult = JObject.Parse(text);
                JToken access_token = tokenResult["access_token"] as JToken;
                string accessToken = access_token.ToString();

                //set expiration time of the access token to 2 months
                string expires = "5183999";

                HttpResponseMessage response = await _httpClient.GetAsync(
                    ApiEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken), Request.CallCancelled);
                response.EnsureSuccessStatusCode();
                text = await response.Content.ReadAsStringAsync();
                JObject user = JObject.Parse(text);

                var context = new DropboxAuthenticatedContext(Context, user, accessToken, expires);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
                if (!string.IsNullOrEmpty(context.UId))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.UId, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.DisplayName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.DisplayName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Country))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Country, context.Country, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.ReferralLink))
                {
                    context.Identity.AddClaim(new Claim("urn:dropbox:referral_link", context.ReferralLink, XmlSchemaString, Options.AuthenticationType));
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

                GenerateCorrelationId(properties);

                string scope = string.Join(",", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);

                //storing the original state value in a cookie and add it to the cookie collection
                HttpCookie stateCookie = new HttpCookie("state", state);
                HttpContext.Current.Response.Cookies.Add(stateCookie);

                //shortening the state string as Dropbox API generates an error for strings longer than 200 bytes
                string csrf_state = state.Substring(0, 200);

                //storing the shortened state value in a cookie and add it to the cookie collection
                HttpCookie csrfStateCookie = new HttpCookie("csrf_state", csrf_state);
                HttpContext.Current.Response.Cookies.Add(csrfStateCookie);

                string authorizationEndpoint =
                    "https://www.dropbox.com/1/oauth2/authorize" +
                        "?response_type=code" +
                        "&client_id=" + Uri.EscapeDataString(Options.AppKey) +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                        "&scope=" + Uri.EscapeDataString(scope) +
                        "&state=" + Uri.EscapeDataString(csrf_state);

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
                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new DropboxReturnEndpointContext(Context, ticket);
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
