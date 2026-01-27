using System.Security.Claims;
using FileFox_Backend.Models;

namespace FileFox_Backend.Services;

public interface ITokenService
{
    string CreateToken(User user);
    string CreateMfaToken(User user);
    ClaimsPrincipal ValidateMfaToken(string token);

}