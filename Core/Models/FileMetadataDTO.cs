using System;

// This is the info we show when listing files (no raw bytes).
namespace FileFox_Backend.Core.Models;

public class FileMetadataDto
{
    public Guid Id { get; init; }
    public required string FileName { get; init; }
    public string? ContentType { get; init; }
    public long Length { get; init; }
    public DateTimeOffset UploadedAt { get; init; }
    public int EncryptedVersion { get; init; }
    public List<string> WrappedKeys { get; set; } = new();
    public string CryptoVersion { get; set; } = "v1";
}