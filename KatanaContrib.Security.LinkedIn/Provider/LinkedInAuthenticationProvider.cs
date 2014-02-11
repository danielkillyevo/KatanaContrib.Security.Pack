using System;
using System.Threading.Tasks;

namespace KatanaContrib.Security.LinkedIn.Provider
{
    public class LinkedInAuthenticationProvider : ILinkedInAuthenticationProvider
    {
        public LinkedInAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }
        public Func<LinkedInAuthenticatedContext, Task> OnAuthenticated { get; set; }        
        public Func<LinkedInReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public virtual Task Authenticated(LinkedInAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(LinkedInReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
