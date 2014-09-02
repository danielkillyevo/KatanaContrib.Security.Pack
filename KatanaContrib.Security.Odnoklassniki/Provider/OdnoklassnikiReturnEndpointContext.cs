using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace KatanaContrib.Security.Odnoklassniki
{
    public class OdnoklassnikiReturnEndpointContext : ReturnEndpointContext
    {
        public OdnoklassnikiReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}