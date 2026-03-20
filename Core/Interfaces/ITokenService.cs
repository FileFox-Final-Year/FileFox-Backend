using FileFox_Backend.Core.Models;
using System.Security.Claims;
using FileFox_Backend.Core.Models;

namespace FileFox_Backend.Core.Interfaces;

public interface ITokenService
{
    string CreateToken(User user);
    string CreateMfaToken(User user);
    ClaimsPrincipal? ValidateMfaToken(string token);

}