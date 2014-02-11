using System.Threading.Tasks;

namespace KatanaContrib.Security.Instagram
{
    public interface IInstagramAuthenticationProvider
    {
        Task Authenticated(InstagramAuthenticatedContext context);
        Task ReturnEndpoint(InstagramReturnEndpointContext context);
    }
}
