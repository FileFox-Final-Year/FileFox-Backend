using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using FileFox_Backend.Infrastructure.Data;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Extensions;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

using FileFox_Backend.Core.Interfaces;
namespace FileFox_Backend.Controllers;

[ApiController]
[Route("keys")]
[Authorize]
[EnableRateLimiting("api")]
public class KeyController : ControllerBase
{
    private readonly ApplicationDbContext _dbContext;

    public KeyController(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }       
    
    // ---------------- REGISTER USER KEY ----------------
    [HttpPost("register")]
    public async Task<IActionResult> RegisterUserKey([FromBody] RegisterUserKeyDto request)
    {
        var userId = User.GetUserId();

        var existing = await _dbContext.UserKeyPairs
            .Where(k => k.UserId == userId && k.RevokedAt == null)
            .OrderByDescending(k => k.KeyVersion)
            .FirstOrDefaultAsync();

        if (existing != null)
            existing.RevokedAt = DateTimeOffset.UtcNow;

        var keyPair = new UserKeyPair
        {
            UserId = userId,
            Algorithm = request.Algorithm,
            PublicKey = request.PublicKey,
            EncryptedPrivateKey = request.EncryptedPrivateKey,
            KeyVersion = (existing?.KeyVersion ?? 0) + 1,
            CreatedAt = DateTimeOffset.UtcNow
        };

        _dbContext.UserKeyPairs.Add(keyPair);
        await _dbContext.SaveChangesAsync();

        return Ok(new { keyPair.KeyVersion });
    }

    // ---------------- GET MY KEY ----------------
    [HttpGet("me")]
    public async Task<IActionResult> GetMyKey()
    {
        var userId = User.GetUserId();

        var key = await _dbContext.UserKeyPairs
            .Where(k => k.UserId == userId && k.RevokedAt == null)
            .OrderByDescending(k => k.KeyVersion)
            .FirstOrDefaultAsync();

        return key == null ? NotFound() : Ok(key);
    }

    // ---------------- GET PUBLIC KEY ----------------
    [AllowAnonymous]
    [HttpGet("public/{userId:guid}")]
    public async Task<IActionResult> GetPublicKey(Guid userId)
    {
        var key = await _dbContext.UserKeyPairs
            .Where(k => k.UserId == userId && k.RevokedAt == null)
            .OrderByDescending(k => k.KeyVersion)
            .Select(k => new { k.PublicKey, k.Algorithm })
            .FirstOrDefaultAsync();

        return key == null ? NotFound() : Ok(key);
    }
}