// These are small message shapes (DTOs) used for sign up and sign in.
namespace FileFox_Backend.Models;

public class RegisterRequest
{
    public required string UserName { get; set; }
    public required string Password { get; set; }
}

public class LoginRequest
{
    public required string UserName { get; set; }
    public required string Password { get; set; }
}

public class AuthResponse
{
    public required string Token { get; set; }
    public required string UserName { get; set; }
    public required string UserId { get; set; }
}