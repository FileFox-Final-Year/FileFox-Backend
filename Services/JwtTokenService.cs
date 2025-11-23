// This makes JWT tokens. A token is like a signed name tag
// that says who you are so the server can trust you.
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FileFox_Backend.Models;
using Microsoft.IdentityModel.Tokens;

namespace FileFox_Backend.Services;

public class JwtTokenService : ITokenService
{
    private readonly byte[] _key;
    private readonly string _issuer;
    private readonly string _audience;

    public JwtTokenService(IConfiguration config)
    {
        // Defaults for demo; can be changed via configuration
        var key = config["Jwt:Key"] ?? "dev-secret-change-me-please-very-long-1234567890";
        _key = Encoding.UTF8.GetBytes(key);
        _issuer = config["Jwt:Issuer"] ?? "InMemoryFileApi";
        _audience = config["Jwt:Audience"] ?? "InMemoryFileApiAudience";
    }

    public string CreateToken(User user)
    {
        var creds = new SigningCredentials(new SymmetricSecurityKey(_key), SecurityAlgorithms.HmacSha256);

        // Claims are pieces of information about the user we put inside the token
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(JwtRegisteredClaimNames.UniqueName, user.UserName),
            new(ClaimTypes.Name, user.UserName)
        };

        // Make a token that expires in a few hours
        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddHours(8),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}