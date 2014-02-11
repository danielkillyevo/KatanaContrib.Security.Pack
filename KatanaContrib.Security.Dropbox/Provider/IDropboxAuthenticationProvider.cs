using System.Threading.Tasks;

namespace KatanaContrib.Security.Dropbox
{
    public interface IDropboxAuthenticationProvider
    {
        Task Authenticated(DropboxAuthenticatedContext context);
        Task ReturnEndpoint(DropboxReturnEndpointContext context);
    }
}
