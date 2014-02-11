using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace KatanaContrib.Security.LinkedIn.Provider
{
    public class LinkedInReturnEndpointContext : ReturnEndpointContext
    {
        public LinkedInReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
