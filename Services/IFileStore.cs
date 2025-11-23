
using FileFox_Backend.Models;
using Microsoft.AspNetCore.Http;

namespace FileFox_Backend.Services;

public interface IFileStore
{
    Task<Guid> SaveAsync(Guid userId, IFormFile file, CancellationToken cancellationToken = default);
    IEnumerable<FileRecord> List(Guid userId);
    bool TryGet(Guid userId, Guid id, out FileRecord record);
    bool Delete(Guid userId, Guid id);
    void Clear(Guid userId);
}