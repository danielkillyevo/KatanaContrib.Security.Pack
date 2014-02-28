using System;
using System.Threading.Tasks;

namespace KatanaContrib.Security.VK
{
    public class VkAuthenticationProvider : IVkAuthenticationProvider
    {
        public VkAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        public Func<VkAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<VkReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public virtual Task Authenticated(VkAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(VkReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
