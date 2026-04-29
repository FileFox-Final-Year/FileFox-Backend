using FileFox_Backend.Core.Models;

public interface IFileStore
{
    Task<Guid> SaveAsync(Guid userId, IFormFile file, string? encryptedMetadata = null, string? recoveryWrappedKey = null, string? wrappedFileKey = null, CancellationToken ct = default);
    Task<IEnumerable<FileRecord>> ListAsync(Guid userId, CancellationToken ct = default);
    Task<FileRecord?> GetAsync(Guid userId, Guid fileId);
    Task<bool> DeleteAsync(Guid userId, Guid fileId);
    Task ClearAsync(Guid userId);
}
