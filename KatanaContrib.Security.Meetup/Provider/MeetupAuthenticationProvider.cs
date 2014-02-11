using System;
using System.Threading.Tasks;

namespace KatanaContrib.Security.Meetup
{

    public class MeetupAuthenticationProvider : IMeetupAuthenticationProvider
    {
        public MeetupAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        public Func<MeetupAuthenticatedContext, Task> OnAuthenticated { get; set; }

        public Func<MeetupReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public virtual Task Authenticated(MeetupAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(MeetupReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
