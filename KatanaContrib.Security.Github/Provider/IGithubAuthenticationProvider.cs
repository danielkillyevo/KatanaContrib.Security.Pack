using System.Threading.Tasks;

namespace KatanaContrib.Security.Github
{
    public interface IGithubAuthenticationProvider
    {
        Task Authenticated(GithubAuthenticatedContext context);
        Task ReturnEndpoint(GithubReturnEndpointContext context);
    }
}
