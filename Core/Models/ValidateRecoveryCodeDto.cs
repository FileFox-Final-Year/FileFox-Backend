namespace FileFox_Backend.Core.Models;

public class ValidateRecoveryCodeDto
{
    public required string RecoveryCode { get; set; }
    public required int KeyVersion { get; set; }
}
