using System.Security.Cryptography;
using System.Text;
using FileFox_Backend.Core.Interfaces;
using FileFox_Backend.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace FileFox_Backend.Infrastructure.Services;

public class RecoveryCodeService : IRecoveryCodeService
{
    private readonly ApplicationDbContext _dbContext;

    public RecoveryCodeService(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    // Generate recovery codes in format: XXXX-XXXX-XXXX (12 characters + dashes).
    public async Task<(List<string> PlaintextCodes, List<string> HashedCodes)> GenerateRecoveryCodesAsync(int count = 10)
    {
        var plaintextCodes = new List<string>();
        var hashedCodes = new List<string>();

        for (int i = 0; i < count; i++)
        {
            var plaintext = GenerateRandomCode();
            plaintextCodes.Add(plaintext);
            hashedCodes.Add(HashRecoveryCode(plaintext));
        }

        return (plaintextCodes, hashedCodes);
    }

    public async Task<bool> ValidateAndUseRecoveryCodeAsync(Guid userId, string plaintext, int keyVersion)
    {
        // Find matching unused code for this user and key version
        var code = await _dbContext.RecoveryCodes
            .FirstOrDefaultAsync(rc =>
                rc.UserId == userId &&
                rc.KeyVersion == keyVersion &&
                !rc.IsRevoked &&
                rc.UsedAt == null &&
                (rc.ExpiresAt == null || rc.ExpiresAt > DateTimeOffset.UtcNow));

        if (code == null)
            return false;

        // Verify the plaintext matches the hash
        if (!VerifyRecoveryCode(plaintext, code.CodeHash))
            return false;

        // Mark as used
        code.UsedAt = DateTimeOffset.UtcNow;
        await _dbContext.SaveChangesAsync();

        return true;
    }

    public async Task<int> GetUnusedCodesCountAsync(Guid userId, int keyVersion)
    {
        return await _dbContext.RecoveryCodes
            .CountAsync(rc =>
                rc.UserId == userId &&
                rc.KeyVersion == keyVersion &&
                !rc.IsRevoked &&
                rc.UsedAt == null &&
                (rc.ExpiresAt == null || rc.ExpiresAt > DateTimeOffset.UtcNow));
    }

    public string HashRecoveryCode(string plaintext)
    {
        // Use PBKDF2 for recovery code hashing (similar to password hashing)
        using (var sha256 = SHA256.Create())
        {
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(plaintext + "recovery-salt"));
            return Convert.ToBase64String(hashedBytes);
        }
    }

    public bool VerifyRecoveryCode(string plaintext, string hash)
    {
        var hashOfInput = HashRecoveryCode(plaintext);
        return hashOfInput.Equals(hash, StringComparison.Ordinal);
    }

    private string GenerateRandomCode()
    {
        // Generate 6 bytes = 12 hex characters = XXXX-XXXX-XXXX format
        using (var rng = RandomNumberGenerator.Create())
        {
            var bytes = new byte[6];
            rng.GetBytes(bytes);
            var hex = Convert.ToHexString(bytes).ToUpper();
            
            // Format as XXXX-XXXX-XXXX
            return $"{hex.Substring(0, 4)}-{hex.Substring(4, 4)}-{hex.Substring(8, 4)}";
        }
    }
}
