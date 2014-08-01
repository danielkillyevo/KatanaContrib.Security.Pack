using System;
using System.Threading.Tasks;

namespace KatanaContrib.Security.MyMail
{
    public class MyMailAuthenticationProvider : IMyMailAuthenticationProvider
    {
        public MyMailAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        public Func<MyMailAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<MyMailReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public virtual Task Authenticated(MyMailAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(MyMailReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}