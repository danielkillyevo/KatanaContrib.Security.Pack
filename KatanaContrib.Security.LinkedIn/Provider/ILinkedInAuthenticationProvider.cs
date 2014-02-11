using System.Threading.Tasks;

namespace KatanaContrib.Security.LinkedIn.Provider
{
    public interface ILinkedInAuthenticationProvider
    {
        Task Authenticated(LinkedInAuthenticatedContext context);
        Task ReturnEndpoint(LinkedInReturnEndpointContext context);
    }
}
