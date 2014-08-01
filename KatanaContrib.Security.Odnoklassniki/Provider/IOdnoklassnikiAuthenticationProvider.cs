using System.Threading.Tasks;

namespace KatanaContrib.Security.Odnoklassniki
{
    public interface IOdnoklassnikiAuthenticationProvider
    {
        Task Authenticated(OdnoklassnikiAuthenticatedContext context);
        Task ReturnEndpoint(OdnoklassnikiReturnEndpointContext context);
    }
}