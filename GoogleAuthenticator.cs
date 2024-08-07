using System.Security.Cryptography;
using System.Web;

namespace Outsystems.GoogleAuthenticator
{
    public class GoogleAuthenticator : IGoogleAuthenticator
    {
        private static string Rfc6238(byte[] key, Int64 Timestamp, int size)
        {
            var data = BitConverter.GetBytes(Timestamp).Reverse().ToArray();
            byte[] Hmac = new HMACSHA1(key).ComputeHash(data);
            int offset = Hmac.Last() & 0x0F;
            string ssPassword = ((
                ((Hmac[offset + 0] & 0x7f) << 24) |
                ((Hmac[offset + 1] & 0xff) << 16) |
                ((Hmac[offset + 2] & 0xff) << 8) |
                (Hmac[offset + 3] & 0xff)
                    ) % Math.Pow(10, size)).ToString();

            ssPassword = new string('0', size - ssPassword.Length) + ssPassword;
            return ssPassword;
        }

        private static Int64 GetUnixTimestamp(DateTime ssInstant)
        {
            return Convert.ToInt64(Math.Round((ssInstant.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds));
        }

        public string GenerateCode(string Secret)
        {
            DateTime instant = DateTime.Now;

            byte[]? key = Base32.FromBase32String(Secret);

            if (key == null) return "";

            return Rfc6238(key, Convert.ToInt64(GetUnixTimestamp(instant) / 30), 6);
        }

        public string GenerateSecret()
        {
            byte[] res = new byte[10]; // 10bytes * 8 = 80bits
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(res);
            }

            return Base32.ToBase32String(res) ?? "";
        }

        public string GetCodeURL(string Issuer, string Secret, string UserIdentifier = "")
        {
            // https://code.google.com/p/google-authenticator/wiki/KeyUriFormat

            return String.Format("otpauth://totp/{0}{1}?secret={2}&issuer={0}",
                HttpUtility.UrlEncode(Issuer),
                String.IsNullOrEmpty(UserIdentifier) ? "" : ("%3A" + HttpUtility.UrlEncode(UserIdentifier)),
                HttpUtility.UrlEncode(Secret));

            
        }

        public bool ValidateCode(string Secret, string Code)
        {
            bool valid = false;
            
            byte[]? key = Base32.FromBase32String(Secret);

            if (key == null) return valid;

            Int64 curr_timestamp = Convert.ToInt64(GetUnixTimestamp(DateTime.Now) / 30);

            string current = Rfc6238(key, curr_timestamp, 6);
            string previous = Rfc6238(key, curr_timestamp - 1, 6);
            string next = Rfc6238(key, curr_timestamp + 1, 6);

            valid = current == Code || previous == Code || next == Code;

            return valid;
        }


    }
}