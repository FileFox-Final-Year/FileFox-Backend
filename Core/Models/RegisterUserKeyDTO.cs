namespace FileFox_Backend.Core.Models;

public class RegisterUserKeyDto
{
    public required string Algorithm { get; set; }
    public required string PublicKey { get; set; }
    public required string EncryptedPrivateKey { get; set; }
    public string? EncryptedPrivateKeyRecovery { get; set; }
}