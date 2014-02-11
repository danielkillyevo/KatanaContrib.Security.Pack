using System;
using System.Threading.Tasks;

namespace KatanaContrib.Security.Instagram
{
    public class InstagramAuthenticationProvider : IInstagramAuthenticationProvider
    {
        public InstagramAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        public Func<InstagramAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<InstagramReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public virtual Task Authenticated(InstagramAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(InstagramReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
