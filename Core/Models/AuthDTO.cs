using System.Text.Json.Serialization;

// These are small message shapes (DTOs) used for sign up and sign in.
namespace FileFox_Backend.Core.Models;

public class RegisterRequest
{
    [JsonPropertyName("username")]
    public required string UserName { get; set; }

    [JsonPropertyName("email")]
    public required string Email { get; set; }

    [JsonPropertyName("password")]
    public required string Password { get; set; }
}

public class LoginRequest
{
    [JsonPropertyName("email")]
    public required string Email { get; set; }

    [JsonPropertyName("password")]
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
    [JsonPropertyName("mfaToken")]
    public string MfaToken { get; set; } = default!;

    [JsonPropertyName("code")]
    public string Code { get; set; } = default!;
}

public class MfaVerifyRequest
{
    [JsonPropertyName("code")]
    public string Code { get; set; } = default!;
}

public class MfaCompleteRequest
{
    [JsonPropertyName("mfaToken")]
    public required string MfaToken { get; set; }

    [JsonPropertyName("code")]
    public required string Code { get; set; }
}

public class RecoveryLoginRequest
{
    [JsonPropertyName("mfaToken")]
    public required string MfaToken { get; set; }

    [JsonPropertyName("recoveryCode")]
    public required string RecoveryCode { get; set; }
}

public class UserInfoResponse
{
    [JsonPropertyName("userName")]
    public required string UserName { get; set; }

    [JsonPropertyName("email")]
    public required string Email { get; set; }

    [JsonPropertyName("mfaEnabled")]
    public bool MfaEnabled { get; set; }

    [JsonPropertyName("profilePicture")]
    public string? ProfilePicture { get; set; }

    [JsonPropertyName("profilePictureContentType")]
    public string? ProfilePictureContentType { get; set; }
}

public class ForgotPasswordRequest
{
    [JsonPropertyName("email")]
    public required string Email { get; set; }
}

public class ResetPasswordRequest
{
    [JsonPropertyName("token")]
    public required string Token { get; set; }

    [JsonPropertyName("newPassword")]
    public required string NewPassword { get; set; }
}