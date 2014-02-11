using System;
using System.Threading.Tasks;

namespace KatanaContrib.Security.Dropbox
{
    public class DropboxAuthenticationProvider : IDropboxAuthenticationProvider
    {
        public DropboxAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        public Func<DropboxAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<DropboxReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public virtual Task Authenticated(DropboxAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(DropboxReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
