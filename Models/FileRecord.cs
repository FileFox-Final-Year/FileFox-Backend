using System;
using System.Runtime.Intrinsics;

namespace FileFox_Backend.Models;

public class FileRecord
{
    public Guid Id { get; init; }
    public Guid UserId { get; set; }
    public string EncryptedFileName { get; set; } = null!;
    public string ManifestBlobPath { get; set; } = null!;
    public int ChunkSize { get; set; }
    public string CryptoVersion { get; set; } = "v1";
    public DateTimeOffset UploadedAt { get; init; } = DateTimeOffset.UtcNow;
    public List<FileKey> Keys { get; set; } = new();
}

