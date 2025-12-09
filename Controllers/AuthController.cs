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

    [AllowAnonymous]
    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken ct)
    {
        if (!ModelState.IsValid)
        return BadRequest(ModelState);

        var (created, user, error) = await _users.RegisterAsync(request.UserName, request.Email, request.Password, ct);

        if (!created)
        {
            return error?.Contains("exists") ?? false
                ? Conflict(new { error })
                : BadRequest(new { error });
        }

        var token = _tokens.CreateToken(user!);

        return Created("/auth/register", new AuthResponse
        {
            Token = token,
            UserName = user!.UserName,
            Email = user!.Email,
            UserId = user!.Id.ToString()
        });
}

    [AllowAnonymous]
    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _users.ValidateCredentialsAsync(request.Email, request.Password);
        if (user == null)
            return Unauthorized(new { error = "Invalid credentials" });

        // Generate access token
        var accessToken = _tokens.CreateToken(user);

        // Generate refresh token
        var refreshToken = await _refreshTokens.GenerateTokenAsync(user.Id);

        return Ok(new
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken.Token
        });
    }

    [AllowAnonymous]
    [HttpPost("refresh")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        // Validate the incoming refresh token
        var refreshToken = await _refreshTokens.ValidateTokenAsync(request.RefreshToken);
        if (refreshToken == null)
            return Unauthorized(new { error = "Invalid or expired refresh token" });

        // Issue a new access token
        var accessToken = _tokens.CreateToken(refreshToken.User!);

        // Revoke the old refresh token
        await _refreshTokens.RevokeTokenAsync(request.RefreshToken);

        // Generate a new refresh token (rotation)
        var newRefreshToken = await _refreshTokens.GenerateTokenAsync(refreshToken.User!.Id);

        // Return new tokens using the DTO
        var response = new RefreshResponse
        {
            AccessToken = accessToken,
            RefreshToken = newRefreshToken.Token
        };

        return Ok(response);
    }
}
