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
    private readonly ILogger<AuthController> _logger;

    public AuthController(IUserStore users, ITokenService tokens, ILogger<AuthController> logger)
    {
        _users = users;
        _tokens = tokens;
        _logger = logger;
    }

    [AllowAnonymous]
    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken ct)
    {
        var (created, user, error) = await _users.RegisterAsync(request.UserName, request.Password, ct);
        if (!created)
        {
            if (string.Equals(error, "User already exists", StringComparison.OrdinalIgnoreCase))
                return Conflict(new { error });
            return BadRequest(new { error });
        }

        var token = _tokens.CreateToken(user!);
        return Created("/auth/register", new AuthResponse
        {
            Token = token,
            UserName = user!.UserName,
            UserId = user!.Id.ToString()
        });
    }

    [AllowAnonymous]
    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken ct)
    {
        var user = await _users.ValidateCredentialsAsync(request.UserName, request.Password, ct);
        if (user is null)
        {
            _logger.LogWarning("Failed login attempt for username {UserName}", request.UserName);
            return Unauthorized(new { error = "Invalid credentials" });
        }

        var token = _tokens.CreateToken(user);
        return Ok(new AuthResponse
        {
            Token = token,
            UserName = user.UserName,
            UserId = user.Id.ToString()
        });
    }
}
