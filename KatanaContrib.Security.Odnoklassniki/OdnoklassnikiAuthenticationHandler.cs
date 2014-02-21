using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace KatanaContrib.Security.Odnoklassniki
{
    public class OdnoklassnikiAuthenticationHandler : AuthenticationHandler<OdnoklassnikiAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string AuthorizationServiceEndpoint = "http://www.odnoklassniki.ru/oauth/authorize";
        private const string TokenEndpoint = "http://api.odnoklassniki.ru/oauth/token.do";
        private const string UserInfoServiceEndpoint = "http://api.odnoklassniki.ru/fb.do";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public OdnoklassnikiAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            //Helper checking if that module called for login
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

                Options.StoreState = state;

                string authorizationEndpoint =
                    AuthorizationServiceEndpoint +
                        "?client_id=" + Uri.EscapeDataString(Options.ClientId) +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                        "&scope=" + Uri.EscapeDataString(scope) +
                        "&response_type=code" +
                        "&v=" + Uri.EscapeDataString(Options.Version);

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

                var context = new OdnoklassnikiReturnEndpointContext(Context, ticket);
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

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = "";

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");

                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(Options.StoreState);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + Uri.SchemeDelimiter + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                //http://api.odnoklassniki.ru/oauth/token.do
                string tokenRequest = TokenEndpoint + "?grant_type=authorization_code&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                                      "&client_secret=" + Uri.EscapeDataString(Options.ClientSecret) +
                                      "&code=" + Uri.EscapeDataString(code) +
                                      "&redirect_uri=" + Uri.EscapeDataString(redirectUri);

                // USE only POST for odnoklassniki.api
                HttpResponseMessage tokenResponse = await _httpClient.PostAsync(tokenRequest, new HttpRequestMessage().Content, Request.CallCancelled);
                tokenResponse.EnsureSuccessStatusCode();
                string text = await tokenResponse.Content.ReadAsStringAsync();
                //IFormCollection form = WebHelpers.ParseForm(text);
                var JsonResponse = JsonConvert.DeserializeObject<dynamic>(text);
                string accessToken = JsonResponse["access_token"];

                //Set the expiration time 60 days (5183999 seconds)
                string expires = "5183999";

                // Signing.
                // Call API methods using access_token instead of session_key parameter
                // Calculate every request signature parameter sig using a little bit different way described in
                // http://dev.odnoklassniki.ru/wiki/display/ok/Authentication+and+Authorization
                // sig = md5( request_params_composed_string+ md5(access_token + application_secret_key)  )
                // Don't include access_token into request_params_composed_string
                var args = new Dictionary<string, string>();
                args.Add("application_key", Options.ClientPublic);
                args.Add("method", "users.getCurrentUser");
                var signature = string.Concat(args.OrderBy(x => x.Key).Select(x => string.Format("{0}={1}", x.Key, x.Value)).ToList());
                signature = (signature + (accessToken + Options.ClientSecret).GetMd5Hash()).GetMd5Hash();
                args.Add("access_token", accessToken);
                args.Add("sig", signature);

                var userInfoLink = UserInfoServiceEndpoint + "?" + string.Join("&", args.Select(x => x.Key + "=" + x.Value));

                HttpResponseMessage graphResponse = await _httpClient.GetAsync(userInfoLink, Request.CallCancelled);
                graphResponse.EnsureSuccessStatusCode();
                text = await graphResponse.Content.ReadAsStringAsync();

                var data = JObject.Parse(text);
                var context = new OdnoklassnikiAuthenticatedContext(Context, data, accessToken, expires);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.DefaultName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.DefaultName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.FullName))
                {
                    context.Identity.AddClaim(new Claim("urn:vkontakte:name", context.FullName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Link))
                {
                    context.Identity.AddClaim(new Claim("urn:vkontakte:link", context.Link, XmlSchemaString, Options.AuthenticationType));
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
    }
}
