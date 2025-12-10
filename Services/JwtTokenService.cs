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

    public JwtTokenService(ISecretProvider secretProvider)
    {
        var key = secretProvider.GetSecret("Jwt:Key");
        _key = Encoding.UTF8.GetBytes(key);

        _issuer = secretProvider.GetSecret("Jwt:Issuer");
        _audience = secretProvider.GetSecret("Jwt:Audience");
    }

    public string CreateToken(User user)
    {
        var creds = new SigningCredentials(new SymmetricSecurityKey(_key), SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new (JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new (ClaimTypes.NameIdentifier, user.Id.ToString()),
            new (JwtRegisteredClaimNames.UniqueName, user.UserName),
            new (ClaimTypes.Name, user.UserName),
            new(ClaimTypes.Role, user.Role)
        };

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