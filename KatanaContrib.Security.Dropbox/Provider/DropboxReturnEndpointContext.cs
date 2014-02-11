using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace KatanaContrib.Security.Dropbox
{
    public class DropboxReturnEndpointContext : ReturnEndpointContext
    {
        public DropboxReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
