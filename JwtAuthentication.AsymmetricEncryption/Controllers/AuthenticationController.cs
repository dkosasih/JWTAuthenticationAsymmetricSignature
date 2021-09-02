using JwtAuthentication.AsymmetricEncryption.Services;
using JwtAuthentication.Shared.Exceptions;
using JwtAuthentication.Shared.Models;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthentication.AsymmetricEncryption.Controllers
{
    [Route("identity/[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly AuthenticationService _authenticationService;

        public AuthenticationController(AuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;
        }

        [HttpPost]
        [Route("{OwnershipId}")]
        public IActionResult Authenticate([FromBody] UserCredentials userCredentials, string ownershipId)
        {
            try
            {
                string token = _authenticationService.Authenticate(userCredentials, ownershipId);
                return Ok(token);
            }
            catch (InvalidCredentialsException)
            {
                return Unauthorized();
            }
        }
    }
}