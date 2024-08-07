using OutSystems.ExternalLibraries.SDK;

namespace Outsystems.GoogleAuthenticator
{
    [OSInterface(Description = "Provides methods to calculate Google Time-based One-time Password (TOTP) described in RFC 6238.", IconResourceName = "GoogleAuthenticator.resources.logo.png")]
    public interface IGoogleAuthenticator
    {
        [OSAction(Description = "Calculates a One Time password based on the secret.", IconResourceName = "GoogleAuthenticator.resources.logo.png", ReturnName = "Code", ReturnType = OSDataType.Text)]
        public string GenerateCode(
            [OSParameter(Description = "80bit Secret key in Base32")]
            string Secret);

        [OSAction(Description = "Creates a new random secret key. Value is a 80bits Base32 string.", IconResourceName = "GoogleAuthenticator.resources.logo.png", ReturnName = "Secret", ReturnType = OSDataType.Text)]
        public string GenerateSecret();

        [OSAction(Description = "Generates a URL to setup a Google Authenticator App.", IconResourceName = "GoogleAuthenticator.resources.logo.png", ReturnName = "URL", ReturnType = OSDataType.Text)]
        public string GetCodeURL(
            [OSParameter(Description = "Name that will identify your application in the Google Authenticator App")]
            string Issuer,
            [OSParameter(Description = "80bit Secret key in Base32")]
            string Secret,
            [OSParameter(Description = "Optional User Identifier (like an email)")]
            string UserIdentifier = "");

        [OSAction(Description = "Creates a new random secret key. Value is a 80bits Base32 string.", IconResourceName = "GoogleAuthenticator.resources.logo.png", ReturnName = "Valid", ReturnType = OSDataType.Boolean)]
        public bool ValidateCode(
            [OSParameter(Description = "80bit Secret key in Base32")]
            string Secret,
            [OSParameter(Description = "TOTP Code")]
            string Code);
    }
}
