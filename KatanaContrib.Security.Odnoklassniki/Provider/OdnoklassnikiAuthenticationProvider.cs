using System;
using System.Threading.Tasks;

namespace KatanaContrib.Security.Odnoklassniki
{
    public class OdnoklassnikiAuthenticationProvider : IOdnoklassnikiAuthenticationProvider
    {
        public OdnoklassnikiAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        public Func<OdnoklassnikiAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<OdnoklassnikiReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public virtual Task Authenticated(OdnoklassnikiAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(OdnoklassnikiReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
