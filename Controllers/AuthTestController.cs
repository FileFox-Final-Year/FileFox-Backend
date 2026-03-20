using FileFox_Backend.Models;
using FileFox_Backend.Services;
using Microsoft.AspNetCore.Mvc;

namespace FileFox_Backend.Controllers;

[ApiController]
[Route("auth/test")]
public class AuthTestController : ControllerBase
{
    private readonly JwtTokenService _jwt;

    public AuthTestController(JwtTokenService jwt)
    {
        _jwt = jwt;
    }

    // GET /auth/test/token
    [HttpGet("token")]
    public IActionResult GetTestToken()
    {
        // Fake user for development/testing
        var user = new User
        {
            Id = Guid.NewGuid(),
            UserName = "devuser",
            Email = "devuser@example.com",
            Role = "User",
            PasswordHash = "dev_test_hash"
        };

        // Generate JWT using your existing JwtTokenService
        var token = _jwt.CreateToken(user);

        return Ok(new { token });
    }
}