using System.Threading.Tasks;

namespace KatanaContrib.Security.StackExchange
{
    public interface IStackExchangeAuthenticationProvider
    {
        Task Authenticated(StackExchangeAuthenticatedContext context);

        Task ReturnEndpoint(StackExchangeReturnEndpointContext context);
    }
}
