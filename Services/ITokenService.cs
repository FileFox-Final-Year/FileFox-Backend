// This interface defines the contract for a token service that creates authentication tokens for users.
using FileFox_Backend.Models;

namespace FileFox_Backend.Services;

public interface ITokenService
{
    string CreateToken(User user);
}