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
        public void UseLinkedInAuthentication_WhenAppParameterIsNull_ShouldThrowArgumentNull()
        {
            var options = new LinkedInAuthenticationOptions();
            IAppBuilder app = null;

            try
            {
                LinkedInAuthenticationExtensions.UseLinkedInAuthentication(app, options);
            }
            catch(ArgumentNullException e)
            {
                StringAssert.Contains(e.Message, "app parameter is null");
            }
            
        }
    }
}
