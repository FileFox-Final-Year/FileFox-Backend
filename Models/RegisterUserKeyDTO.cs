namespace FileFox_Backend.Models;

public class RegisterUserKeyDto
{
    public required string Algorithm { get; set; }
    public required string PublicKey { get; set; }
    public required string EncryptedPrivateKey { get; set; }
}