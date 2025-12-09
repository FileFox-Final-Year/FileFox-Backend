using FileFox_Backend.Data;
using FileFox_Backend.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace FileFox_Backend.Services;

public class RefreshTokenService
{
    private readonly ApplicationDbContext _db;

    public RefreshTokenService(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task<RefreshToken> GenerateTokenAsync(Guid userId, int daysValid = 7)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

        var refreshToken = new RefreshToken
        {
            UserId = userId,
            Token = token,
            ExpiresAt = DateTime.UtcNow.AddDays(daysValid)
        };

        _db.RefreshTokens.Add(refreshToken);
        await _db.SaveChangesAsync();
        return refreshToken;
    }

    public async Task<RefreshToken?> ValidateTokenAsync(string token)
    {
        var refreshToken = await _db.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == token);

        if (refreshToken == null || !refreshToken.IsActive)
            return null;

        return refreshToken;
    }

    public async Task RevokeTokenAsync(string token)
    {
        var refreshToken = await _db.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == token);
        if (refreshToken != null)
        {
            refreshToken.RevokedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync();
        }
    }
}
