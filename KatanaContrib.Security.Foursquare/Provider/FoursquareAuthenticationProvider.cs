using System;
using System.Threading.Tasks;

namespace KatanaContrib.Security.Foursquare
{
    public class FoursquareAuthenticationProvider : IFoursquareAuthenticationProvider
    {
        public FoursquareAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }
        public Func<FoursquareAuthenticatedContext, Task> OnAuthenticated { get; set; }

        public Func<FoursquareReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public virtual Task Authenticated(FoursquareAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(FoursquareReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
