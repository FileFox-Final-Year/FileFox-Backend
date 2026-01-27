// These are small message shapes (DTOs) used for sign up and sign in.
namespace FileFox_Backend.Models;

public class RegisterRequest
{
    public required string UserName { get; set; }
    public required string Email { get; set; }
    public required string Password { get; set; }
}

public class LoginRequest
{
    public required string Email { get; set; }
    public required string Password { get; set; }
}

public class AuthResponse
{
    public required string Token { get; set; }
    public required string UserName { get; set; }
    public required string Email { get; set; }
    public required string UserId { get; set; }
}

public class RefreshRequest
{
    public required string RefreshToken { get; set; }
}

public class RefreshResponse
{
    public required string AccessToken { get; set; }
    public required string RefreshToken { get; set; }
}
public class MfaLoginRequest
{
    public string Email { get; set; } = default!;
    public string Password { get; set; } = default!;
    public string Code { get; set; } = default!;
}

public class MfaVerifyRequest
{
    public string Code { get; set; } = default!;
}

public class MfaCompleteRequest
{
    public required string MfaToken { get; set; }
    public required string Code { get; set; }
}