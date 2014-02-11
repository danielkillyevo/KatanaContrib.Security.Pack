using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using KatanaContrib.Security.LinkedIn;
using Owin;

namespace KatanaContrib.Security.LinkedIn.Tests
{
    [TestClass]
    public class LinkedInAuthenticationExtensionsTests
    {
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void UseLinkedInAuthentication_WhenAppArgumentIsNull_ShouldThrowArgumentNull()
        {
            var options = new LinkedInAuthenticationOptions();
            IAppBuilder app = null;

            LinkedInAuthenticationExtensions.UseLinkedInAuthentication(app, options);
        }

    }
}
