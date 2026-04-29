using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FileFox_Backend.Core.Models;
using Microsoft.IdentityModel.Tokens;

using FileFox_Backend.Core.Interfaces;
namespace FileFox_Backend.Infrastructure.Services;

public class JwtTokenService : ITokenService
{
    private readonly byte[] _key;
    private readonly string _issuer;
    private readonly string _audience;

    public JwtTokenService(ISecretProvider secretProvider)
    {
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        var key = secretProvider.GetSecret("Jwt:Key")
                  ?? throw new InvalidOperationException("JWT key is missing");
        _key = Encoding.UTF8.GetBytes(key);

        _issuer = secretProvider.GetSecret("Jwt:Issuer")
                  ?? throw new InvalidOperationException("JWT issuer is missing");
        _audience = secretProvider.GetSecret("Jwt:Audience")
                    ?? throw new InvalidOperationException("JWT audience is missing");
    }

    public string CreateToken(User user)
    {
        var creds = new SigningCredentials(new SymmetricSecurityKey(_key), SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(JwtRegisteredClaimNames.UniqueName, user.UserName),
            new(ClaimTypes.Name, user.UserName),
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

    public string CreateMfaToken(User user)
    {
        var creds = new SigningCredentials(new SymmetricSecurityKey(_key), SecurityAlgorithms.HmacSha256);

        // MFA token claims
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(JwtRegisteredClaimNames.UniqueName, user.UserName),
            new(ClaimTypes.Name, user.UserName),
            new(ClaimTypes.Role, user.Role),
            new("typ", "mfa") // MFA type indicator
        };

        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(15), // short-lived MFA token
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public ClaimsPrincipal? ValidateMfaToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        var validationParams = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _issuer,
            ValidAudience = _audience,
            IssuerSigningKey = new SymmetricSecurityKey(_key),
            ClockSkew = TimeSpan.Zero,
            NameClaimType = JwtRegisteredClaimNames.Sub,
            RoleClaimType = ClaimTypes.Role
        };

        try
        {
            var principal = tokenHandler.ValidateToken(
                token,
                validationParams,
                out _
            );

            // Ensure this is an MFA token
            if (principal.FindFirst("typ")?.Value != "mfa")
                return null;

            return principal;
        }
        catch (SecurityTokenException)
        {
            return null;
        }
    }

}
