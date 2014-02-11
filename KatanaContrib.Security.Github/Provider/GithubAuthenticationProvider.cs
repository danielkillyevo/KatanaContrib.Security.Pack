using System;
using System.Threading.Tasks;

namespace KatanaContrib.Security.Github
{
    public class GithubAuthenticationProvider : IGithubAuthenticationProvider
    {
        public GithubAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }
        public Func<GithubAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<GithubReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public virtual Task Authenticated(GithubAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(GithubReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
