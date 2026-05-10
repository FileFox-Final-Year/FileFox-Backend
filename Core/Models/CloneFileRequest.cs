namespace FileFox_Backend.Core.Models;

public class CloneFileRequest
{
    public required string WrappedFileKey { get; set; }
    public string? RecoveryWrappedKey { get; set; }
}
