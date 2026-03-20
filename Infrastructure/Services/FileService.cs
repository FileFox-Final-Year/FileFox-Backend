using FileFox_Backend.Core.Models;

using FileFox_Backend.Core.Interfaces;
namespace FileFox_Backend.Infrastructure.Services;

/// <summary>
/// IMPORTANT
/// This service MUST NEVER handle plaintext file uploads.
/// All files are encrypted client-side before reaching the backend.
/// This service is read-only and operates on ciphertext only.
/// </summary>
public class FileService
{
    private readonly IBlobStorageService _blob;

    public FileService(IBlobStorageService blob)
    {
        _blob = blob;
    }

    //SAFE: streaming encrypted chunks out
    public Task<Stream?> GetChunkAsync(Guid fileId, int index)
    {
        return _blob.GetChunkAsync(fileId, index);
    }

    //SAFE: encrypted manifest passthrough
    public Task<Stream?> GetManifestAsync(Guid fileId)
    {
        return _blob.GetManifestAsync(fileId);
    }
}