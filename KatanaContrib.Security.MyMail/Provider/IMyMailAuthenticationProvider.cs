using System.Threading.Tasks;

namespace KatanaContrib.Security.MyMail
{
    public interface IMyMailAuthenticationProvider
    {
        Task Authenticated(MyMailAuthenticatedContext context);
        Task ReturnEndpoint(MyMailReturnEndpointContext context);
    }
}