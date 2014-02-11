using System;
using System.Threading.Tasks;

namespace KatanaContrib.Security.StackExchange
{
    public class StackExchangeAuthenticationProvider : IStackExchangeAuthenticationProvider
    {
        public StackExchangeAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }        
        public Func<StackExchangeAuthenticatedContext, Task> OnAuthenticated { get; set; }        
        public Func<StackExchangeReturnEndpointContext, Task> OnReturnEndpoint { get; set; }   
        public virtual Task Authenticated(StackExchangeAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(StackExchangeReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
