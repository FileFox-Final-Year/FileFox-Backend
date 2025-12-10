using FileFox_Backend.Models;

namespace FileFox_Backend.Services;

public interface ITokenService
{
    string CreateToken(User user);
}