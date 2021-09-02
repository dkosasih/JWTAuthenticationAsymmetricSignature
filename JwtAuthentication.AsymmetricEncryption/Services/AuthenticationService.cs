using JwtAuthentication.Shared.Models;
using JwtAuthentication.Shared.Services;

namespace JwtAuthentication.AsymmetricEncryption.Services
{
    public class AuthenticationService
    {
        private readonly UserService _userService;
        private readonly TokenService _tokenService;

        public AuthenticationService(UserService userService, TokenService tokenService)
        {
            this._userService = userService;
            this._tokenService = tokenService;
        }

        public string Authenticate(UserCredentials userCredentials, string ownershipId)
        {
            _userService.ValidateCredentials(userCredentials);
            string securityToken = _tokenService.GetToken(userCredentials.Username, ownershipId);

            return securityToken;
        }
    }
}
