using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using FileFox_Backend.Models;
using FileFox_Backend.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FileFox_Backend.Controllers;

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly IUserStore _users;
    private readonly ITokenService _tokens;
    private readonly RefreshTokenService _refreshTokens;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IUserStore users,
        ITokenService tokens,
        RefreshTokenService refreshTokens,
        ILogger<AuthController> logger)
    {
        _users = users;
        _tokens = tokens;
        _refreshTokens = refreshTokens;
        _logger = logger;
    }

    // ---------------- REGISTER ----------------
    [AllowAnonymous]
    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken ct)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var (created, user, error) = await _users.RegisterAsync(request.UserName, request.Email, request.Password, ct);

        if (!created)
            return error?.Contains("exists") == true
                ? Conflict(new { error })
                : BadRequest(new { error });

        user!.Role = "User";
        var token = _tokens.CreateToken(user);

        return Created("/auth/register", new AuthResponse
        {
            Token = token,
            UserName = user.UserName,
            Email = user.Email,
            UserId = user.Id.ToString()
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
            return Unauthorized(new { error = "Invalid credentials" });

        if (user.MfaEnabled)
        {
            // Issue short-lived MFA token
            var mfaToken = _tokens.CreateMfaToken(user); // 2–5 minute token
            return Ok(new
            {
                mfaRequired = true,
                message = "MFA required",
                mfaToken
            });
        }

        var accessToken = _tokens.CreateToken(user);
        var refreshToken = await _refreshTokens.GenerateTokenAsync(user.Id);

        return Ok(new
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken.Token
        });
    }

    // ---------------- LOGIN (STEP 2: MFA) ----------------
    [AllowAnonymous]
    [HttpPost("login/mfa")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> LoginWithMfa([FromBody] MfaLoginRequest req)
    {
        var user = await _users.ValidateCredentialsAsync(req.Email, req.Password);
        if (user == null || !user.MfaEnabled || user.MfaSecret == null)
            return Unauthorized(new { error = "Invalid credentials or MFA not enabled" });

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
        var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userIdClaim == null) return Unauthorized();

        var userId = Guid.Parse(userIdClaim);
        var (found, user) = await _users.TryGetByIdAsync(userId);
        if (!found || user == null) return Unauthorized();

        var secret = OtpNet.KeyGeneration.GenerateRandomKey(20);
        var base32 = OtpNet.Base32Encoding.ToString(secret);

        user.MfaSecret = base32;
        user.MfaEnabled = false;
        user.MfaEnabledAt = null;

        await _users.UpdateAsync(user);

        return Ok(new
        {
            base32Secret = base32,
            otpAuthUri =
                $"otpauth://totp/FileFox:{user.Email}?secret={base32}&issuer=FileFox"
        });
    }

    // ---------------- MFA VERIFY ----------------
    [Authorize]
    [HttpPost("mfa/verify")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> VerifyMfa([FromBody] MfaVerifyRequest req)
    {
        var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userIdClaim == null) return Unauthorized();

        var userId = Guid.Parse(userIdClaim);
        var (found, user) = await _users.TryGetByIdAsync(userId);

        if (!found || user == null || user.MfaSecret == null)
            return BadRequest();

        var totp = new OtpNet.Totp(OtpNet.Base32Encoding.ToBytes(user.MfaSecret));
        if (!totp.VerifyTotp(req.Code, out _, new OtpNet.VerificationWindow(1, 1)))
            return Unauthorized(new { error = "Invalid code" });

        user.MfaEnabled = true;
        user.MfaEnabledAt = DateTimeOffset.UtcNow;

        await _users.UpdateAsync(user);

        return Ok();
    }
}
