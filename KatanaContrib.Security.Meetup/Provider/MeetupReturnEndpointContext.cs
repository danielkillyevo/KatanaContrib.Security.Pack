using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace KatanaContrib.Security.Meetup
{
    public class MeetupReturnEndpointContext : ReturnEndpointContext
    {
        public MeetupReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
