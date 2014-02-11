using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace KatanaContrib.Security.Instagram
{
    public class InstagramReturnEndpointContext : ReturnEndpointContext
    {
        public InstagramReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
