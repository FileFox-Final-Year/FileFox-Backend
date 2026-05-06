using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Extensions;
using FileFox_Backend.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

using FileFox_Backend.Core.Interfaces;
namespace FileFox_Backend.Controllers;

[ApiController]
[Route("auth")]
[EnableRateLimiting("auth")]
public class AuthController : ControllerBase
{
    private readonly IUserStore _users;
    private readonly ITokenService _tokens;
    private readonly RefreshTokenService _refreshTokens;
    private readonly AuditService _audit;

    public AuthController(
        IUserStore users,
        ITokenService tokens,
        RefreshTokenService refreshTokens,
        AuditService audit)
    {
        _users = users;
        _tokens = tokens;
        _refreshTokens = refreshTokens;
        _audit = audit;
    }

    // ---------------- REGISTER ----------------
    [AllowAnonymous]
    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken ct)
    {
        var (created, user, error) =
            await _users.RegisterAsync(request.UserName, request.Email, request.Password, ct);

        if (!created)
            return Conflict(new { error });

        await _audit.LogAsync(user!.Id, "User Registered");

        var token = _tokens.CreateToken(user!);

        return Created("", new AuthResponse
        {
            Token = token,
            UserId = user.Id.ToString(),
            UserName = user.UserName,
            Email = user.Email
        });
    }

    // ---------------- LOGIN (STEP 1) ----------------
    [AllowAnonymous]
    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _users.ValidateCredentialsAsync(request.Email, request.Password);
        if (user == null)
            return Unauthorized();

        if (user.MfaEnabled)
        {
            return Ok(new
            {
                mfaRequired = true,
                mfaToken = _tokens.CreateMfaToken(user)
            });
        }

        await _audit.LogAsync(user.Id, "User Logged In");

        return Ok(new
        {
            AccessToken = _tokens.CreateToken(user),
            RefreshToken = (await _refreshTokens.GenerateTokenAsync(user.Id)).Token
        });
    }

    // ---------------- LOGIN (STEP 2: MFA) ----------------
    [AllowAnonymous]
    [HttpPost("login/mfa")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> LoginWithMfa([FromBody] MfaLoginRequest req)
    {
        var principal = _tokens.ValidateMfaToken(req.MfaToken);
        if (principal == null)
            return Unauthorized(new { error = "Invalid or expired MFA token" });

        var userIdString = principal.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userIdString, out var userId))
            return Unauthorized();

        var (found, user) = await _users.TryGetByIdAsync(userId);
        if (!found || user == null || !user.MfaEnabled || user.MfaSecret == null)
            return Unauthorized(new { error = "User not found or MFA not enabled" });

        var totp = new OtpNet.Totp(OtpNet.Base32Encoding.ToBytes(user.MfaSecret));
        if (!totp.VerifyTotp(req.Code, out _, new OtpNet.VerificationWindow(1, 1)))
            return Unauthorized(new { error = "Invalid MFA code" });

        var accessToken = _tokens.CreateToken(user);
        var refreshToken = await _refreshTokens.GenerateTokenAsync(user.Id);

        return Ok(new
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken.Token
        });
    }

    // ---------------- LOGIN (RECOVERY) ----------------
    [AllowAnonymous]
    [HttpPost("login/recovery")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> LoginWithRecoveryCode([FromBody] RecoveryLoginRequest req)
    {
        var principal = _tokens.ValidateMfaToken(req.MfaToken);
        if (principal == null)
            return Unauthorized(new { error = "Invalid or expired MFA token" });

        var userIdString = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userIdString, out var userId))
            return Unauthorized();

        var (found, user) = await _users.TryGetByIdAsync(userId);
        if (!found || user == null || !user.MfaEnabled || user.MfaRecoveryCodes == null)
            return Unauthorized(new { error = "User not found or MFA recovery not available" });

        var hashedCodes = user.MfaRecoveryCodes.Split(',').ToList();
        string? matchedHashedCode = null;

        foreach (var hashedCode in hashedCodes)
        {
            if (BCrypt.Net.BCrypt.Verify(req.RecoveryCode, hashedCode))
            {
                matchedHashedCode = hashedCode;
                break;
            }
        }

        if (matchedHashedCode == null)
            return Unauthorized(new { error = "Invalid recovery code" });

        // Remove the used code
        hashedCodes.Remove(matchedHashedCode);
        user.MfaRecoveryCodes = string.Join(",", hashedCodes);
        await _users.UpdateAsync(user);

        await _audit.LogAsync(user.Id, "User Logged In (Recovery Code)");

        var accessToken = _tokens.CreateToken(user);
        var refreshToken = await _refreshTokens.GenerateTokenAsync(user.Id);

        return Ok(new
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken.Token
        });
    }

    // ---------------- REFRESH ----------------
    [AllowAnonymous]
    [HttpPost("refresh")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        // Validate the incoming refresh token
        var refreshToken = await _refreshTokens.ValidateTokenAsync(request.RefreshToken);
        if (refreshToken == null || refreshToken.User == null)
            return Unauthorized(new { error = "Invalid or expired refresh token" });

        // Issue a new access token
        var accessToken = _tokens.CreateToken(refreshToken.User);

        // Revoke the old refresh token
        await _refreshTokens.RevokeTokenAsync(request.RefreshToken);
        // Generate a new refresh token (rotation)
        var newRefreshToken = await _refreshTokens.GenerateTokenAsync(refreshToken.User.Id);

        return Ok(new RefreshResponse
        {
            AccessToken = accessToken,
            RefreshToken = newRefreshToken.Token
        });
    }

    // ---------------- MFA SETUP ----------------
    [Authorize]
    [HttpPost("mfa/setup")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> SetupMfa()
    {
        var userId = User.GetUserId();
        var (_, user) = await _users.TryGetByIdAsync(userId);
        if (user == null) return Unauthorized();

        var secret = OtpNet.KeyGeneration.GenerateRandomKey(20);
        user.MfaSecret = OtpNet.Base32Encoding.ToString(secret);
        user.MfaEnabled = false;

        // Generate recovery codes
        var recoveryCodes = Enumerable.Range(0, 10).Select(_ => Guid.NewGuid().ToString("N")[..12]).ToList();
        user.MfaRecoveryCodes = string.Join(",", recoveryCodes.Select(c => BCrypt.Net.BCrypt.HashPassword(c)));

        await _users.UpdateAsync(user);

        var issuer = "FileFox";
        var encodedIssuer = Uri.EscapeDataString(issuer);
        var encodedEmail = Uri.EscapeDataString(user.Email);

        return Ok(new
        {
            base32Secret = user.MfaSecret,
            otpAuthUri =
                $"otpauth://totp/{encodedIssuer}:{encodedEmail}?secret={user.MfaSecret}&issuer={encodedIssuer}",
            recoveryCodes = recoveryCodes
        });
    }

    // ---------------- MFA VERIFY ----------------
    [Authorize]
    [HttpPost("mfa/verify")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> VerifyMfa([FromBody] MfaVerifyRequest req)
    {
        var userId = User.GetUserId();
        var (_, user) = await _users.TryGetByIdAsync(userId);
        if (user?.MfaSecret == null) return BadRequest();

        var totp = new OtpNet.Totp(OtpNet.Base32Encoding.ToBytes(user.MfaSecret));
        if (!totp.VerifyTotp(req.Code, out _, new OtpNet.VerificationWindow(1, 1)))
            return Unauthorized();

        user.MfaEnabled = true;
        user.MfaEnabledAt = DateTimeOffset.UtcNow;

        await _users.UpdateAsync(user);
        return Ok();
    }

    // ---------------- ME ----------------
    [Authorize]
    [HttpGet("me")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> GetMe()
    {
        var userId = User.GetUserId();
        var (found, user) = await _users.TryGetByIdAsync(userId);

        if (!found || user == null)
            return Unauthorized();

        return Ok(new UserInfoResponse
        {
            UserName = user.UserName,
            Email = user.Email,
            MfaEnabled = user.MfaEnabled,
            ProfilePicture = user.ProfilePicture != null ? Convert.ToBase64String(user.ProfilePicture) : null,
            ProfilePictureContentType = user.ProfilePictureContentType
        });
    }

    // ---------------- FORGOT PASSWORD ----------------
    [AllowAnonymous]
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest req)
    {
        var user = await _users.GetByEmailAsync(req.Email);
        if (user == null) return Ok(); // Don't reveal user existence

        user.PasswordResetToken = Guid.NewGuid().ToString("N");
        user.PasswordResetTokenExpires = DateTimeOffset.UtcNow.AddHours(1);

        await _users.UpdateAsync(user);

        // In a real app, send an email. For now, we return it in the response for demo purposes.
        return Ok(new { resetToken = user.PasswordResetToken });
    }

    // ---------------- RESET PASSWORD ----------------
    [AllowAnonymous]
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest req)
    {
        var user = await _users.GetByResetTokenAsync(req.Token);
        if (user == null || user.PasswordResetTokenExpires < DateTimeOffset.UtcNow)
            return BadRequest(new { error = "Invalid or expired reset token" });

        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.NewPassword);
        user.PasswordResetToken = null;
        user.PasswordResetTokenExpires = null;

        await _users.UpdateAsync(user);
        await _audit.LogAsync(user.Id, "Password Reset");

        return Ok();
    }

    // ---------------- PROFILE PICTURE ----------------
    [Authorize]
    [HttpPost("profile-picture")]
    public async Task<IActionResult> UploadProfilePicture(IFormFile file)
    {
        if (file == null || file.Length == 0) return BadRequest("No file uploaded");
        if (file.Length > 1 * 1024 * 1024) return BadRequest("File too large (max 1MB)");

        var userId = User.GetUserId();
        var (_, user) = await _users.TryGetByIdAsync(userId);
        if (user == null) return Unauthorized();

        using var ms = new MemoryStream();
        await file.CopyToAsync(ms);
        user.ProfilePicture = ms.ToArray();
        user.ProfilePictureContentType = file.ContentType;

        await _users.UpdateAsync(user);
        return Ok();
    }

    // ---------------- MFA DISABLE ----------------
    [Authorize]
    [HttpPost("mfa/disable")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> DisableMfa()
    {
        var userId = User.GetUserId();
        var (_, user) = await _users.TryGetByIdAsync(userId);
        if (user == null) return Unauthorized();

        user.MfaEnabled = false;
        user.MfaSecret = null;
        user.MfaRecoveryCodes = null;

        await _users.UpdateAsync(user);
        return Ok();
    }
}
