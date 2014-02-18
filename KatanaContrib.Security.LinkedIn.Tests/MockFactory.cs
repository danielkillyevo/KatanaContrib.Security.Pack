using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Moq;
using Microsoft.Owin;

namespace KatanaContrib.Security.LinkedIn.Tests
{
    public static class MockFactory
    {
        public static IOwinContext CreateStubOwinContext()
        {
            return CreateOwinContextMock().Object;
        }

        public static Mock<IOwinContext> CreateOwinContextMock()
        {
            Mock<IOwinContext> mock = new Mock<IOwinContext>(MockBehavior.Strict);
            mock.Setup(c => c.Request).Returns(CreateDummyOwinRequest());
            return mock;
        }

        public static IOwinRequest CreateDummyOwinRequest()
        {
            return new Mock<IOwinRequest>(MockBehavior.Strict).Object;
        }
    }
}
