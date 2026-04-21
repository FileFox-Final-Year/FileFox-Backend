namespace FileFox_Backend.Core.Models;
public class FileManifest
{
    public Guid Id { get; set; }
    public Guid FileId { get; set; }
    public string ManifestHash { get; set; } = null!;
    public int ChunkCount { get; set; }
}