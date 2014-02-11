using System.Threading.Tasks;

namespace KatanaContrib.Security.Meetup
{
    public interface IMeetupAuthenticationProvider
    {
        Task Authenticated(MeetupAuthenticatedContext context);

        Task ReturnEndpoint(MeetupReturnEndpointContext context);
    }
}
