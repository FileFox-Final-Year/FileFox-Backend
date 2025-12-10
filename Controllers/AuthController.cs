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
        _logger.LogInformation("Registration attempt for email {Email}", request.Email);

        if (!ModelState.IsValid)
        {
            _logger.LogWarning("Registration failed for email {Email} due to invalid model state", request.Email);
            return BadRequest(ModelState);
        }

        var (created, user, error) = await _users.RegisterAsync(request.UserName, request.Email, request.Password, ct);

        if (!created)
        {
            if (error?.Contains("exists") ?? false)
            {
                _logger.LogWarning("Registration failed: user already exists for email {Email}", request.Email);
                return Conflict(new { error });
            }
            else
            {
                _logger.LogWarning("Registration failed for email {Email}: {Error}", request.Email, error);
                return BadRequest(new { error });
            }
        }

        _logger.LogInformation("User registered successfully with email {Email} and ID {UserId}", user!.Email, user!.Id);

        user!.Role = "User";
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
        _logger.LogInformation("Login attempt for {Email}", request.Email);

        var user = await _users.ValidateCredentialsAsync(request.Email, request.Password);

        if (user == null)
        {
            _logger.LogWarning("Failed login attempt for {Email}", request.Email);
            return Unauthorized(new { error = "Invalid credentials" });
        }

        _logger.LogInformation("User {Email} logged in successfully", request.Email);

        var accessToken = _tokens.CreateToken(user);
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
