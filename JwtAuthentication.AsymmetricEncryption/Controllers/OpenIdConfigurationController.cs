using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using JwtAuthentication.AsymmetricEncryption.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuthentication.AsymmetricEncryption.Controllers
{
    public class OpenIdConfigurationController : ControllerBase
    {
        [HttpGet()]
        [Route(".well-known/openid-configuration")]
        public IActionResult OpenIdConfig()
        {
            Console.WriteLine("OpenID Config Requested");

            return Ok(new
            {
                // TODO: fix magic string with dev, staging, production, or Env var
                jwks_uri = "http://localhost:5000/jwks"
            });
        }

        [HttpGet()]
        [Route("jwks")]
        public IActionResult Jwk()
        {
            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();

            foreach (var privateKeyPath in GetAllPemFiles())
            {
                var privateKey = System.IO.File.ReadAllText(privateKeyPath);
                var jsonWebKey = JwkUtils.JwkFromPrivateKey(privateKey);
                
                jsonWebKeySet.Keys.Add(jsonWebKey);
            }
            
            Console.WriteLine("JWKs Requested");
            return Ok(jsonWebKeySet);
        }

        private IEnumerable<string> GetAllPemFiles()
        {
            return Directory.GetFiles(Path.Combine(AppContext.BaseDirectory, "Certificates")).Where(x=>x.EndsWith("pem"));
        }
    }
}