using JwtAuthentication.AsymmetricEncryption.Certificates;
using JwtAuthentication.Shared;
using JwtAuthentication.Shared.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JwtAuthentication.AsymmetricEncryption.Services
{
    public class TokenService
    {
        private readonly UserRepository _userRepository;
        private readonly SigningAudienceCertificate _signingAudienceCertificate;

        public TokenService(UserRepository userRepository)
        {
            _userRepository = userRepository;
            _signingAudienceCertificate = new SigningAudienceCertificate();
        }

        public string GetToken(string username, string ownershipId)
        {
            var user = _userRepository.GetUser(username);
            var tokenDescriptor = GetTokenDescriptor(user, ownershipId);

            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(securityToken);

            return token;
        }

        private SecurityTokenDescriptor GetTokenDescriptor(User user, string ownershipId)
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = "TradeAuth",
                Audience = ownershipId,
                Subject = new ClaimsIdentity(user.Claims()),
                Expires = DateTime.UtcNow.AddMinutes(60),
                SigningCredentials = _signingAudienceCertificate.GetAudienceSigningKey()
            };

            return tokenDescriptor;
        }
    }
}