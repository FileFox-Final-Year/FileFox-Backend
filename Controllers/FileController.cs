using System.Security.Claims;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure;
using FileFox_Backend.Infrastructure.Extensions;
using FileFox_Backend.Infrastructure.Services;
using FileFox_Backend.Infrastructure.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
namespace FileFox_Backend.Controllers;

[ApiController]
[Route("files")]
[Authorize]
[EnableRateLimiting("api")]
public class FilesController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IBlobStorageService _blob;
    private readonly IFileStore _fileStore;
    private readonly AuditService _audit;

    public FilesController(ApplicationDbContext db, IBlobStorageService blob, IFileStore fileStore, AuditService audit)
    {
        _db = db;
        _blob = blob;
        _fileStore = fileStore;
        _audit = audit;
    }
    
     // ---------------- INIT UPLOAD ----------------
    [HttpPost("init")]
    public async Task<IActionResult> Init([FromBody] InitUploadDto dto)
    {
        var userId = User.GetUserId();
        if (userId == Guid.Empty) return Unauthorized();

        var fileId = Guid.NewGuid();

        // store encrypted manifest header
        var headerBytes = Convert.FromBase64String(dto.EncryptedManifestHeader);
        await using var memoryStream = new MemoryStream(headerBytes);
        var manifestPath = await _blob.PutManifestAsync(fileId, memoryStream);

        var record = new FileRecord
        {
            Id = fileId,
            UserId = userId,
            EncryptedFileName = dto.EncryptedFileName,
            EncryptedMetadata = dto.EncryptedMetadata,
            TotalSize = dto.TotalSize,
            ContentType = dto.ContentType,
            ChunkSize = dto.ChunkSize,
            CryptoVersion = dto.CryptoVersion,
            ManifestBlobPath = manifestPath,
            UploadedAt = DateTime.UtcNow,
            RecoveryWrappedKey = dto.RecoveryWrappedKey
        };

        var key = new FileKey
        {
            FileRecordId = fileId,
            UserId = userId,
            WrappedFileKey = dto.WrappedFileKey
        };

        _db.Files.Add(record);
        _db.FileKeys.Add(key);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(userId, "Init Upload", fileId);

        return Ok(new { fileId });
    }

    // ---------------- UPLOAD CHUNK ----------------
    [HttpPut("{id:guid}/chunks/{index:int}")]
    [DisableRequestSizeLimit]
    public async Task<IActionResult> UploadChunk(Guid id, int index)
    {
        var userId = User.GetUserId();
        var record = await _db.Files.FirstOrDefaultAsync(f => f.Id == id && f.UserId == userId);
        if (record == null) return NotFound();

        await _blob.PutChunkAsync(id, index, Request.Body);
        return Ok();
    }

    // ---------------- DIRECT UPLOAD ----------------
    [HttpPost("upload")]
    [DisableRequestSizeLimit]
    public async Task<IActionResult> Upload([FromForm] UploadFileRequest request, CancellationToken ct)
    {
        var userId = User.GetUserId();
        if (userId == Guid.Empty) return Unauthorized();

        if (request.File == null) return BadRequest("No file uploaded");

        var fileId = await _fileStore.SaveAsync(
            userId,
            request.File,
            request.EncryptedMetadata,
            request.RecoveryWrappedKey,
            request.WrappedFileKey,
            ct);

        await _audit.LogAsync(userId, "Direct Upload", fileId);

        return Ok(new { fileId });
    }

    // ---------------- COMPLETE UPLOAD ----------------
    [HttpPost("{id:guid}/complete")]
    public async Task<IActionResult> Complete(Guid id)
    {
        var userId = User.GetUserId();
        var record = await _db.Files.FirstOrDefaultAsync(f => f.Id == id && f.UserId == userId);

        if (record == null) return NotFound();

        return Ok(new { status = "Completed", fileId = id });
    }

    // ---------------- SHARE FILE ----------------
    [HttpPost("{id:guid}/share")]
    public async Task<IActionResult> Share(Guid id, [FromBody] ShareFileRequest request)
    {
        var userId = User.GetUserId();
        var file = await _db.Files.FirstOrDefaultAsync(f => f.Id == id && f.UserId == userId);

        if (file == null)
            return NotFound("File not found or you are not the owner");

        var recipient = await _db.Users.FirstOrDefaultAsync(u => u.Email == request.RecipientEmail);
        if (recipient == null)
            return NotFound("Recipient not found");

        if (recipient.Id == userId)
            return BadRequest("You cannot share a file with yourself");

        var existingKey = await _db.FileKeys
            .FirstOrDefaultAsync(k => k.FileRecordId == id && k.UserId == recipient.Id);

        if (existingKey != null)
        {
            existingKey.WrappedFileKey = request.WrappedFileKey;
            existingKey.CreatedAt = DateTimeOffset.UtcNow;
        }
        else
        {
            var newKey = new FileKey
            {
                FileRecordId = id,
                UserId = recipient.Id,
                WrappedFileKey = request.WrappedFileKey
            };
            _db.FileKeys.Add(newKey);
        }

        await _db.SaveChangesAsync();
        await _audit.LogAsync(userId, $"Shared File with {request.RecipientEmail}", id);

        return Ok(new { message = "File shared successfully" });
    }

    // ---------------- LIST FILES ----------------
    [HttpGet]
    public async Task<IActionResult> List()
    {
        var userId = User.GetUserId();
        var userEmail = User.FindFirstValue(ClaimTypes.Email);
        var files = await _fileStore.ListAsync(userId);

        var dtos = files.Select(f => new FileMetadataDto
        {
            Id = f.Id,
            FileName = f.EncryptedFileName,
            EncryptedMetadata = f.EncryptedMetadata,
            ContentType = f.ContentType,
            Length = f.TotalSize,
            UploadedAt = f.UploadedAt,
            CryptoVersion = f.CryptoVersion,
            WrappedKeys = f.Keys.Select(k => k.WrappedFileKey).ToList(),
            RecoveryWrappedKey = f.RecoveryWrappedKey,
            OwnerEmail = userEmail,
            IsOwner = true
        });

        return Ok(dtos);
    }

    // ---------------- LIST SHARED FILES ----------------
    [HttpGet("shared")]
    public async Task<IActionResult> ListShared()
    {
        var userId = User.GetUserId();

        var sharedFiles = await _db.FileKeys
            .Include(k => k.FileRecord)
            .Where(k => k.UserId == userId && k.FileRecord.UserId != userId)
            .ToListAsync();

        var ownerIds = sharedFiles.Select(k => k.FileRecord.UserId).Distinct().ToList();
        var owners = await _db.Users
            .Where(u => ownerIds.Contains(u.Id))
            .ToDictionaryAsync(u => u.Id, u => u.Email);

        var dtos = sharedFiles.Select(k => new FileMetadataDto
        {
            Id = k.FileRecord.Id,
            FileName = k.FileRecord.EncryptedFileName,
            EncryptedMetadata = k.FileRecord.EncryptedMetadata,
            ContentType = k.FileRecord.ContentType,
            Length = k.FileRecord.TotalSize,
            UploadedAt = k.FileRecord.UploadedAt,
            CryptoVersion = k.FileRecord.CryptoVersion,
            WrappedKeys = new List<string> { k.WrappedFileKey },
            RecoveryWrappedKey = null, // Recipients don't get recovery keys
            OwnerEmail = owners.GetValueOrDefault(k.FileRecord.UserId),
            IsOwner = false
        });

        return Ok(dtos);
    }

    // ---------------- GET METADATA ----------------
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetMetadata(Guid id)
    {
        var userId = User.GetUserId();
        var record = await _db.Files
            .Include(f => f.Keys)
            .FirstOrDefaultAsync(f => f.Id == id && (f.UserId == userId || f.Keys.Any(k => k.UserId == userId)));

        if (record == null) return NotFound();

        var isOwner = record.UserId == userId;
        var owner = await _db.Users.FindAsync(record.UserId);

        var dto = new FileMetadataDto
        {
            Id = record.Id,
            FileName = record.EncryptedFileName,
            EncryptedMetadata = record.EncryptedMetadata,
            ContentType = record.ContentType,
            Length = record.TotalSize,
            UploadedAt = record.UploadedAt,
            CryptoVersion = record.CryptoVersion,
            WrappedKeys = isOwner
                ? record.Keys.Select(k => k.WrappedFileKey).ToList()
                : record.Keys.Where(k => k.UserId == userId).Select(k => k.WrappedFileKey).ToList(),
            RecoveryWrappedKey = isOwner ? record.RecoveryWrappedKey : null,
            OwnerEmail = owner?.Email,
            IsOwner = isOwner
        };

        return Ok(dto);
    }

    // ---------------- GET MANIFEST ----------------
    [HttpGet("{id:guid}/manifest")]
    public async Task<IActionResult> GetManifest(Guid id)
    {
        var userId = User.GetUserId();
        var record = await _db.Files
            .Include(f => f.Keys)
            .FirstOrDefaultAsync(f => f.Id == id && (f.UserId == userId || f.Keys.Any(k => k.UserId == userId)));
        if (record == null) return NotFound();

        var stream = await _blob.GetManifestAsync(id);
        if (stream == null) return NotFound("Manifest not found");

        return File(stream, "application/octet-stream", "manifest");
    }

    // ---------------- GET CHUNK ----------------
    [HttpGet("{id:guid}/chunks/{index:int}")]
    public async Task<IActionResult> GetChunk(Guid id, int index)
    {
        var userId = User.GetUserId();
        var record = await _db.Files
            .Include(f => f.Keys)
            .FirstOrDefaultAsync(f => f.Id == id && (f.UserId == userId || f.Keys.Any(k => k.UserId == userId)));
        if (record == null) return NotFound();

        var stream = await _blob.GetChunkAsync(id, index);
        if (stream == null) return NotFound("Chunk not found");

        return File(stream, "application/octet-stream", $"chunk_{index}");
    }

    // ---------------- CLONE FILE ----------------
    [HttpPost("{id:guid}/clone")]
    public async Task<IActionResult> Clone(Guid id, [FromBody] CloneFileRequest request)
    {
        var userId = User.GetUserId();
        // User must have access to the file (either owner or shared with)
        var record = await _db.Files
            .Include(f => f.Keys)
            .FirstOrDefaultAsync(f => f.Id == id && (f.UserId == userId || f.Keys.Any(k => k.UserId == userId)));

        if (record == null) return NotFound("File not found or no access");

        // Create a new FileRecord for the current user
        var newFileId = Guid.NewGuid();

        // Clone blobs (manifest and chunks)
        var blobs = await _db.Blobs.Where(b => b.FileId == id).ToListAsync();
        foreach (var blob in blobs)
        {
            _db.Blobs.Add(new BlobData
            {
                FileId = newFileId,
                ChunkIndex = blob.ChunkIndex,
                Data = blob.Data
            });
        }

        var newRecord = new FileRecord
        {
            Id = newFileId,
            UserId = userId,
            EncryptedFileName = record.EncryptedFileName,
            EncryptedMetadata = record.EncryptedMetadata,
            ContentType = record.ContentType,
            TotalSize = record.TotalSize,
            ChunkSize = record.ChunkSize,
            CryptoVersion = record.CryptoVersion,
            ManifestBlobPath = record.ManifestBlobPath.Replace(id.ToString(), newFileId.ToString()),
            UploadedAt = DateTimeOffset.UtcNow,
            RecoveryWrappedKey = request.RecoveryWrappedKey // Recipient provides their own recovery key for their copy
        };

        var newKey = new FileKey
        {
            FileRecordId = newFileId,
            UserId = userId,
            WrappedFileKey = request.WrappedFileKey
        };

        _db.Files.Add(newRecord);
        _db.FileKeys.Add(newKey);
        await _db.SaveChangesAsync();

        await _audit.LogAsync(userId, "Cloned Shared File", newFileId);

        return Ok(new { fileId = newFileId });
    }

    // ---------------- DOWNLOAD FULL FILE ----------------
    [HttpGet("{id:guid}/download")]
    public async Task<IActionResult> Download(Guid id)
    {
        var userId = User.GetUserId();
        var record = await _db.Files
            .Include(f => f.Keys)
            .FirstOrDefaultAsync(f => f.Id == id && (f.UserId == userId || f.Keys.Any(k => k.UserId == userId)));

        if (record == null) return NotFound();

        if (record.CryptoVersion == "v1-simple")
        {
            var stream = await _blob.GetChunkAsync(id, 0);
            if (stream == null) return NotFound("File content not found");
            return File(stream, record.ContentType ?? "application/octet-stream", record.EncryptedFileName);
        }

        // For chunked files, we can provide a combined stream or instructions to download chunks.
        // For a true "download" endpoint, let's try to stream all chunks.
        return new FileCallbackResult(record.ContentType ?? "application/octet-stream", async (outputStream, _) =>
        {
            int index = 0;
            while (true)
            {
                var chunkStream = await _blob.GetChunkAsync(id, index);
                if (chunkStream == null) break;

                await chunkStream.CopyToAsync(outputStream);
                await chunkStream.DisposeAsync();
                index++;
            }
        })
        {
            FileDownloadName = record.EncryptedFileName
        };
    }

    // ---------------- DELETE FILE ----------------
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var userId = User.GetUserId();

        // Log before deleting so the FileRecord still exists for the foreign key
        await _audit.LogAsync(userId, "Delete File", id);

        var success = await _fileStore.DeleteAsync(userId, id);
        if (!success) return NotFound();

        return Ok();
    }
}
