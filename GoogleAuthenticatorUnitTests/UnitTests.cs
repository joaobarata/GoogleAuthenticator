namespace GoogleAuthenticatorUnitTests
{
    public class UnitTests
    {
        [Fact]
        public void ValidateCode()
        {
            GoogleAuthenticator gA = new();

            string secret = gA.GenerateSecret();

            string code = gA.GenerateCode(secret);

            bool result = gA.ValidateCode(secret, code);

            Assert.True(result);
        }

        [Fact]
        public void GenerateURL()
        {
            GoogleAuthenticator gA = new();

            string secret = gA.GenerateSecret();

            string code = gA.GenerateCode(secret);

            string URL = gA.GetCodeURL("My App", secret);

            Assert.True(URL.Length>0);
        }

        

    }
}