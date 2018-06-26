using Microsoft.Owin;
using Microsoft.Owin.Security.Google;
using Owin;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System.Security.Claims;
using System.Web;

namespace OWINAuthentication.IdentityProviders
{
    public class GoogleAuthentication : IdentityProvidersProcessor
    {
        public GoogleAuthentication(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {

        }

        /// <summary>
        /// Identityprovidr name. Has to match the configuration
        /// </summary>
        protected override string IdentityProviderName
        {
            get { return "Google"; }
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider identityProvider = this.GetIdentityProvider();
            string authenticationType = this.GetAuthenticationType();

            //Google
            var googleProvider = new GoogleOAuth2AuthenticationProvider()
            {
                OnAuthenticated = (context) =>
                {
                    // transform all claims
                    ClaimsIdentity identity = context.Identity;
                    foreach (Transformation current in identityProvider.Transformations)
                    {
                        current.Transform(identity, new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                    }
                    return System.Threading.Tasks.Task.FromResult(0);
                },

                OnReturnEndpoint = (context) =>
                {
                    if (context.Request.Query["state"] != null)
                    {
                        var state = HttpUtility.ParseQueryString(context.Request.Query["state"]);
                        //todo: do something with it.
                    }

                    return System.Threading.Tasks.Task.FromResult(0);
                }
            };

            GoogleOAuth2AuthenticationOptions googleOptions = new GoogleOAuth2AuthenticationOptions();
            googleOptions.ClientId = "839319546746-bpijo8mlsi4isld86jeah76974u1n39i.apps.googleusercontent.com";
            googleOptions.ClientSecret = "RrqhHCb5hf5_0DYrTOsLnP-F";
            googleOptions.Provider = googleProvider;
            googleOptions.CallbackPath = new PathString("/signin-google");

            args.App.UseGoogleAuthentication(googleOptions);
        }
    }
}