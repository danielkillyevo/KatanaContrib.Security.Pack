using System.Threading.Tasks;

namespace KatanaContrib.Security.VK
{
    public interface IVkAuthenticationProvider
    {
        Task Authenticated(VkAuthenticatedContext context);
        Task ReturnEndpoint(VkReturnEndpointContext context);
    }
}