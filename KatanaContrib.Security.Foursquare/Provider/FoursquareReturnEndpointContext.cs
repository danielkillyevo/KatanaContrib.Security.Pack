using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace KatanaContrib.Security.Foursquare
{
    public class FoursquareReturnEndpointContext : ReturnEndpointContext
    {
        public FoursquareReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
