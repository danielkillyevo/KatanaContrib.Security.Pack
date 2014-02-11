// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

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

namespace KatanaContrib.Security.Meetup
{
    internal class MeetupAuthenticationHandler : AuthenticationHandler<MeetupAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "https://secure.meetup.com/oauth2/access";
        private const string ApiEndpoint = "https://api.meetup.com/members";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public MeetupAuthenticationHandler(HttpClient httpClient, ILogger logger)
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

                //Meetup replaces '_' charactors with spaces in the 'state' parameter when returns. 
                //Resetting it back to it's original string
                state = state.Replace(' ', '_');

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
                    "&client_id=" + Uri.EscapeDataString(Options.Key) +
                    "&client_secret=" + Uri.EscapeDataString(Options.Secret);

                //Meetup API requires to send the token request as a POST message.
                //Initiated a new HttpRequestMessage object to use as a parameter for PostAsync method.
                HttpRequestMessage request = new HttpRequestMessage();
                HttpResponseMessage tokenResponse = await _httpClient.PostAsync(TokenEndpoint + "?" + tokenRequest, request.Content, Request.CallCancelled);
                tokenResponse.EnsureSuccessStatusCode();
                string text = await tokenResponse.Content.ReadAsStringAsync();

                //Object is returned as a JSON Object. 
                //Parsing the string contains JSON text to a JSON Object.
                JObject details = JObject.Parse(text);

                string accessToken = null;
                string expires = null;

                foreach(var x in details)
                {
                    if(x.Key == "access_token")
                    {
                        accessToken = (string)x.Value;
                    }

                    if(x.Key == "expires_in")
                    {
                        expires = (string)x.Value;
                    }
                }

                HttpResponseMessage apiResponse = await _httpClient.GetAsync(
                    ApiEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken) +
                    "&member_id=self" + "&key=" + Uri.EscapeDataString(Options.Key), Request.CallCancelled);

                apiResponse.EnsureSuccessStatusCode();

                text = await apiResponse.Content.ReadAsStringAsync();

                //Convert JSON string to a JSON Object
                JObject info = JObject.Parse(text);

                //Extract the 'results' JToken from info
                JToken results = info["results"];
                JToken userinfo = results.First;
                JObject user = userinfo as JObject;

                var context = new MeetupAuthenticatedContext(Context, user, accessToken, expires);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Name))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.City))
                {
                    context.Identity.AddClaim(new Claim("urn:meetup:city", context.City, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Country))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Country, context.Country, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Link))
                {
                    context.Identity.AddClaim(new Claim("urn:meetup:link", context.Link, XmlSchemaString, Options.AuthenticationType));
                }
                if(!string.IsNullOrEmpty(context.Joined))
                {
                    context.Identity.AddClaim(new Claim("urn:meetup:joined", context.Joined, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.PhotoUrl))
                {
                    context.Identity.AddClaim(new Claim("urn:meetup:photourl", context.PhotoUrl, XmlSchemaString, Options.AuthenticationType));
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

                string scope = string.Join(",", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);

                string authorizationEndpoint =
                    "https://secure.meetup.com/oauth2/authorize" +
                        "?response_type=code" +
                        "&client_id=" + Uri.EscapeDataString(Options.Key) +
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

                var context = new MeetupReturnEndpointContext(Context, ticket);
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
