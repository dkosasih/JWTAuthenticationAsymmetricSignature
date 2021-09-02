namespace JwtAuthentication.AsymmetricEncryption.RP.Models
{
    public class Auth
    {
        public string Issuer { get; set; }
        public AsymmetricConfiguration AsymmetricConfiguration { get; set; }
    }

    public class AsymmetricConfiguration
    {
        public string Authority { get; set; }
    }
}