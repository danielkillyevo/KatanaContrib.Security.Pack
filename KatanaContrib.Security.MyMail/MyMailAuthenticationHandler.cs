using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace KatanaContrib.Security.MyMail
{
    public class MyMailAuthenticationHandler : AuthenticationHandler<MyMailAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public MyMailAuthenticationHandler(HttpClient httpClient, ILogger logger)
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
            AuthenticationResponseChallenge challenge =
                Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    string.Format("{0}{1}{2}{3}", Request.Scheme, Uri.SchemeDelimiter, Request.Host, Request.PathBase);

                string currentUri =
                    string.Format("{0}{1}{2}", baseUri, Request.Path, Request.QueryString);

                string redirectUri =
                    string.Format("{0}{1}", baseUri, Options.CallbackPath);

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                string state = Options.StateDataFormat.Protect(properties);

                Options.StoreState = state;

                string authorizationEndpoint =
                    "https://connect.mail.ru/oauth/authorize?" +
                    "client_id=" + Uri.EscapeDataString(Options.ClientId) +
                    "&response_type=code" +
                    "&redirect_uri=" + Uri.EscapeDataString(redirectUri);

                Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

        //<summary>step 2.0
        //Called at start of page request, before site controllers
        //</summary>
        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        //step 2.1
        //called at start of page request - checking if request match with "{host}/signin-mymail" url {?code=*******************}
        //if matched - making AuthenticationTicket 
        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                AuthenticationTicket ticket = await AuthenticateAsync();
                //call Task<AuthenticationTicket> AuthenticateCoreAsync() step 2.3
                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new MyMailReturnEndpointContext(Context, ticket)
                {
                    SignInAsAuthenticationType =
                        Options.SignInAsAuthenticationType,
                    RedirectUri = ticket.Properties.RedirectUri
                };

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (
                        !string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType,
                            StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType,
                            grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
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
                string code = string.Empty;

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

                IDictionary<string, string> parameters = new Dictionary<string, string>();
                parameters.Add("client_id", Options.ClientId);
                parameters.Add("client_secret", Options.ClientSecret);
                parameters.Add("grant_type", "authorization_code");
                parameters.Add("code", code);
                parameters.Add("redirect_uri", redirectUri);

                using (HttpContent httpContent = new FormUrlEncodedContent(parameters.ToList()))
                {
                    using (HttpResponseMessage responseMessage =
                        await _httpClient.PostAsync("https://connect.mail.ru/oauth/token", httpContent))
                    {
                        if (responseMessage.IsSuccessStatusCode)
                        {
                            string s = await responseMessage.Content.ReadAsStringAsync();

                            var dynamicObject = JsonConvert.DeserializeObject<dynamic>(s);

                            string accessToken = dynamicObject["access_token"];
                            string expires = dynamicObject["expires_in"];
                            string userid = dynamicObject["x_mailru_vid"];

                            var myMailClient = new MyMailClient(Options.ClientId, userid, accessToken,
                                Options.PrivateKey);

                            string userInfoRequestUri = myMailClient.BuildMethodRequestUri("users.getInfo");
                            s = await _httpClient.GetStringAsync(userInfoRequestUri);
                            JArray userInfoArray = JArray.Parse(s);
                            var context = new MyMailAuthenticatedContext(Context, (JObject) userInfoArray.First(),
                                accessToken, expires)
                            {
                                Identity = new ClaimsIdentity(
                                    Options.AuthenticationType,
                                    ClaimsIdentity.DefaultNameClaimType,
                                    ClaimsIdentity.DefaultRoleClaimType)
                            };

                            AddClaim(context, "urn:mymail:accesstoken", context.AccessToken);
                            AddClaim(context, "urn:mymail:link", context.Link);

                            AddClaim(context, ClaimTypes.NameIdentifier, context.Id);
                            AddClaim(context, ClaimTypes.Name, context.FullName);
                            AddClaim(context, ClaimTypes.GivenName, context.FirstName);
                            AddClaim(context, ClaimTypes.Surname, context.LastName);
                            AddClaim(context, ClaimTypes.Email, context.Email);

                            context.Properties = properties;

                            await Options.Provider.Authenticated(context);

                            return new AuthenticationTicket(context.Identity, context.Properties);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        private void AddClaim(MyMailAuthenticatedContext context, string type, string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                context.Identity.AddClaim(new Claim(type, value, XmlSchemaString, Options.AuthenticationType));
            }
        }
    }
}