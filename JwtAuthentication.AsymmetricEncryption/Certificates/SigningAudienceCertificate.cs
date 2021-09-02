using Microsoft.IdentityModel.Tokens;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace JwtAuthentication.AsymmetricEncryption.Certificates
{
    public class SigningAudienceCertificate : IDisposable
    {
        private readonly RSA _rsa;

        public SigningAudienceCertificate()
        {
            _rsa = RSA.Create();
        }

        public SigningCredentials GetAudienceSigningKey()
        {
            var privateXmlKey = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Certificates", "private_key.pem"));
            _rsa.ImportFromPem(privateXmlKey);

            return new SigningCredentials(
                key: new RsaSecurityKey(_rsa),
                algorithm: SecurityAlgorithms.RsaSha256);
        }

        public void Dispose()
        {
            _rsa?.Dispose();
        }
    }
}
