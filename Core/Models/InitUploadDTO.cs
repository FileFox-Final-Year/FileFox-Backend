namespace FileFox_Backend.Core.Models;

public class InitUploadDto
{
    public string EncryptedFileName { get; set; } = null!;
    public string EncryptedManifestHeader { get; set; } = null!;
    public string WrappedFileKey { get; set; } = null!;
    public int ChunkSize { get; set; }
    public long TotalSize { get; set; }
    public string? ContentType { get; set; }
    public string CryptoVersion { get; set; } = "v1";
}