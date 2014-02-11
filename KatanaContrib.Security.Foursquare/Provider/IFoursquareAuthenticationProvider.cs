using System.Threading.Tasks;

namespace KatanaContrib.Security.Foursquare
{
    public interface IFoursquareAuthenticationProvider
    {
        Task Authenticated(FoursquareAuthenticatedContext context);

        Task ReturnEndpoint(FoursquareReturnEndpointContext context);
    }
}
