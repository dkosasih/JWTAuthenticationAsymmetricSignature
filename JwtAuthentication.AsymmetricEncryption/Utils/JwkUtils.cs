using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace JwtAuthentication.AsymmetricEncryption.Utils
{
    public static class JwkUtils
    {
        public static JsonWebKey JwkFromPrivateKey(string privateKey)
        {
            return CreateJwkFromPublicKey(CreatePublicKeyFromPrivateKey(privateKey));
        }

        private static string CreatePublicKeyFromPrivateKey(string privateKey)
        {
            using var reader = new StringReader(privateKey);

            var pemReader = new PemReader(reader);
            var pemObject = pemReader.ReadObject();

            var rsaPrivateCrtKeyParameters = (RsaPrivateCrtKeyParameters)pemObject;
            var rsaKeyParameters = new RsaKeyParameters(false, rsaPrivateCrtKeyParameters.Modulus, rsaPrivateCrtKeyParameters.PublicExponent);

            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(rsaKeyParameters);
            pemWriter.Writer.Flush();
            var publicKeyPem = textWriter.ToString();

            return publicKeyPem;
        }

        private static JsonWebKey CreateJwkFromPublicKey(string publicKey)
        {
            using var textReader = new StringReader(publicKey);

            var pubkeyReader = new PemReader(textReader);
            var keyParameters = (RsaKeyParameters)pubkeyReader.ReadObject();
            var e = Base64UrlEncoder.Encode(keyParameters.Exponent.ToByteArrayUnsigned());
            var n = Base64UrlEncoder.Encode(keyParameters.Modulus.ToByteArrayUnsigned());
            var dict = new Dictionary<string, string>() {
                {"e", e},
                {"kty", "RSA"},
                {"n", n}
            };
            var hash = SHA256.Create();
            var hashBytes = hash.ComputeHash(System.Text.Encoding.ASCII.GetBytes(JsonConvert.SerializeObject(dict)));
            var jsonWebKey = new JsonWebKey()
            {
                Kid = Base64UrlEncoder.Encode(hashBytes),
                Kty = "RSA",
                E = e,
                N = n
            };

            return jsonWebKey;
        }
    }
}