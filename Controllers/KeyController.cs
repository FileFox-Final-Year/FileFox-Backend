using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using FileFox_Backend.Infrastructure.Data;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Extensions;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using FileFox_Backend.Core.Interfaces;
using Microsoft.AspNetCore.RateLimiting;

namespace FileFox_Backend.Controllers;

[ApiController]
[Route("keys")]
[Authorize]
[EnableRateLimiting("KeyLimiter")]
public class KeyController : ControllerBase
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IRecoveryCodeService _recoveryCodeService;

    public KeyController(ApplicationDbContext dbContext, IRecoveryCodeService recoveryCodeService)
    {
        _dbContext = dbContext;
        _recoveryCodeService = recoveryCodeService;
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
            Id = Guid.NewGuid(),
            UserId = userId,
            Algorithm = request.Algorithm,
            PublicKey = request.PublicKey,
            EncryptedPrivateKey = request.EncryptedPrivateKey,
            EncryptedPrivateKeyRecovery = request.EncryptedPrivateKeyRecovery,
            KeyVersion = (existing?.KeyVersion ?? 0) + 1,
            CreatedAt = DateTimeOffset.UtcNow
        };

        _dbContext.UserKeyPairs.Add(keyPair);
        await _dbContext.SaveChangesAsync();

        // Generate recovery codes for this new key version
        var (plaintextCodes, hashedCodes) = await _recoveryCodeService.GenerateRecoveryCodesAsync(10);

        foreach (var hash in hashedCodes)
        {
            _dbContext.RecoveryCodes.Add(new RecoveryCode
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                CodeHash = hash,
                KeyVersion = keyPair.KeyVersion,
                CreatedAt = DateTimeOffset.UtcNow
            });
        }

        await _dbContext.SaveChangesAsync();

        // Return key version and plaintext recovery codes (shown once to user)
        return Ok(new 
        { 
            keyPair.KeyVersion,
            recoveryCodes = plaintextCodes,
            message = "Save these recovery codes in a safe place. You can use them to recover access from a new device."
        });
    }

    // ---------------- GET MY KEY (NEW DEVICE) ----------------
    [HttpGet("me")]
    public async Task<IActionResult> GetMyKey()
    {
        var userId = User.GetUserId();

        var key = await _dbContext.UserKeyPairs
            .Where(k => k.UserId == userId && k.RevokedAt == null)
            .OrderByDescending(k => k.KeyVersion)
            .Select(k => new
            {
                k.KeyVersion,
                k.PublicKey,
                k.EncryptedPrivateKey,
                k.Algorithm,
                k.CreatedAt
            })
            .FirstOrDefaultAsync();

        if (key == null)
            return NotFound();

        return Ok(key);
    }

    // ---------------- GET PUBLIC KEY ----------------
    [AllowAnonymous]
    [HttpGet("public/{userId:guid}")]
    public async Task<IActionResult> GetPublicKey(Guid userId)
    {
        var key = await _dbContext.UserKeyPairs
            .Where(k => k.UserId == userId && k.RevokedAt == null)
            .OrderByDescending(k => k.KeyVersion)
            .Select(k => new
            {
                k.PublicKey,
                k.Algorithm,
                k.KeyVersion
            })
            .FirstOrDefaultAsync();

        if (key == null)
            return NotFound();

        return Ok(key);
    }

    // ---------------- GET RECOVERY BLOB (NEW DEVICE) ----------------
    [HttpGet("me/recovery")]
    public async Task<IActionResult> GetRecoveryBlob()
    {
        var userId = User.GetUserId();

        var key = await _dbContext.UserKeyPairs
            .Where(k => k.UserId == userId && k.RevokedAt == null)
            .OrderByDescending(k => k.KeyVersion)
            .Select(k => new
            {
                k.KeyVersion,
                k.EncryptedPrivateKeyRecovery,
                unusedRecoveryCodesCount = _dbContext.RecoveryCodes
                    .Count(rc =>
                        rc.UserId == userId &&
                        rc.KeyVersion == k.KeyVersion &&
                        !rc.IsRevoked &&
                        rc.UsedAt == null &&
                        (rc.ExpiresAt == null || rc.ExpiresAt > DateTimeOffset.UtcNow))
            })
            .FirstOrDefaultAsync();

        if (key?.EncryptedPrivateKeyRecovery == null)
            return NotFound("No recovery blob configured. Please register a recovery key.");

        return Ok(key);
    }

    // ---------------- VALIDATE RECOVERY CODE ----------------
    [HttpPost("recovery/validate")]
    public async Task<IActionResult> ValidateRecoveryCode([FromBody] ValidateRecoveryCodeDto request)
    {
        var userId = User.GetUserId();

        var isValid = await _recoveryCodeService.ValidateAndUseRecoveryCodeAsync(
            userId,
            request.RecoveryCode,
            request.KeyVersion);

        if (!isValid)
            return Unauthorized(new { message = "Invalid or already used recovery code" });

        var unusedCount = await _recoveryCodeService.GetUnusedCodesCountAsync(userId, request.KeyVersion);

        return Ok(new 
        { 
            message = "Recovery code validated and marked as used",
            unusedCodesRemaining = unusedCount
        });
    }

    // ---------------- ROTATE RECOVERY CODES ----------------
    [HttpPost("recovery/rotate")]
    public async Task<IActionResult> RotateRecoveryCodes()
    {
        var userId = User.GetUserId();

        // Get current key version
        var keyVersion = await _dbContext.UserKeyPairs
            .Where(k => k.UserId == userId && k.RevokedAt == null)
            .OrderByDescending(k => k.KeyVersion)
            .Select(k => k.KeyVersion)
            .FirstOrDefaultAsync();

        if (keyVersion == 0)
            return NotFound("No active key pair found");

        // Revoke old codes
        var oldCodes = await _dbContext.RecoveryCodes
            .Where(rc => rc.UserId == userId && rc.KeyVersion == keyVersion && !rc.IsRevoked)
            .ToListAsync();

        foreach (var code in oldCodes)
        {
            code.IsRevoked = true;
        }

        // Generate new codes
        var (plaintextCodes, hashedCodes) = await _recoveryCodeService.GenerateRecoveryCodesAsync(10);

        foreach (var hash in hashedCodes)
        {
            _dbContext.RecoveryCodes.Add(new RecoveryCode
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                CodeHash = hash,
                KeyVersion = keyVersion,
                CreatedAt = DateTimeOffset.UtcNow
            });
        }

        await _dbContext.SaveChangesAsync();

        return Ok(new 
        { 
            recoveryCodes = plaintextCodes,
            message = "Recovery codes rotated successfully. Save these new codes in a safe place."
        });
    }
}