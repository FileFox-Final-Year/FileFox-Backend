using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace FileFox_Backend.Core.Interfaces;

public interface IRecoveryCodeService
{
    // Generate a list of recovery codes and return both the plaintext codes and hashed versions. Client receives plaintext codes once; backend stores hashed versions.
    Task<(List<string> PlaintextCodes, List<string> HashedCodes)> GenerateRecoveryCodesAsync(int count = 10);
    // Validate and mark a recovery code as used. Returns true if valid and unused.
    Task<bool> ValidateAndUseRecoveryCodeAsync(Guid userId, string plaintext, int keyVersion);
    // Get count of unused recovery codes for a user.
    Task<int> GetUnusedCodesCountAsync(Guid userId, int keyVersion);
    // Hash a plaintext recovery code.
    string HashRecoveryCode(string plaintext);
    // Verify a plaintext code against a hashed code.
    bool VerifyRecoveryCode(string plaintext, string hash);
}
