using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using KatanaContrib.Security.LinkedIn.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Owin;
using Newtonsoft.Json.Linq;
using Moq;

namespace KatanaContrib.Security.LinkedIn.Tests
{
    [TestClass]
    public class LinkedInAuthenticatedContextTests
    {
        [TestMethod]
        public void LinkedInAuthenticatedContext_WhenUserParameterIsNull_ThrowArgumentNullException()
        {
            IOwinContext context = CreateStubOwinContext();
            string userInfo = "{\"id\":\"3lwM3bUvfJ\",\"first-name\":\"Nirosha\",\"last-name\":\"Gihan\",\"formatted-name\":\"Nirosha Gihan\"}";
            JObject user = null;
            string accessToken = "2975638759247325yugfysh8274585";
            string expires = "3600";

            try
            {
                LinkedInAuthenticatedContext linkedinContext = new LinkedInAuthenticatedContext(context, user, accessToken, expires);
            }
            catch(ArgumentNullException e)
            {
                StringAssert.Contains(e.Message, "user is null");
            }
        }

        private static IOwinContext CreateStubOwinContext()
        {
            return CreateOwinContextMock().Object;
        }

        private static Mock<IOwinContext> CreateOwinContextMock()
        {
            Mock<IOwinContext> mock = new Mock<IOwinContext>(MockBehavior.Strict);
            mock.Setup(c => c.Request).Returns(CreateDummyOwinRequest());
            return mock;
        }

        private static IOwinRequest CreateDummyOwinRequest()
        {
            return new Mock<IOwinRequest>(MockBehavior.Strict).Object;
        }
    }
}
