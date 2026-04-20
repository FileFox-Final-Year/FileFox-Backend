using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Extensions;
using FileFox_Backend.Infrastructure.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using FileFox_Backend.Infrastructure.Results;
using FileAccessEntity = FileFox_Backend.Core.Models.FileAccess;
namespace FileFox_Backend.Controllers;

[ApiController]
[Route("files")]
[Authorize]
public class FilesController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IBlobStorageService _blob;
    private readonly IFileStore _fileStore;

    public FilesController(ApplicationDbContext db, IBlobStorageService blob, IFileStore fileStore)
    {
        _db = db;
        _blob = blob;
        _fileStore = fileStore;
    }
    
    // ---------------- AUTH HELPER ----------------
    private async Task<FileRecord?> GetFileIfAuthorized(Guid fileId)
    {
        var userId = User.GetUserId();

        var file = await _db.Files
            .Include(f => f.Keys)
            .FirstOrDefaultAsync(f => f.Id == fileId);

        if (file == null) return null;

        // Check if user is the owner or has access via FileAccess
            var hasAccess = await _db.FileAccesses.AnyAsync(a =>
                a.FileRecordId == fileId &&
                a.UserId == userId &&
                a.FileEncryptionVersion == file.FileEncryptionVersion &&
                a.RevokedAt == null);

        return hasAccess ? file : null;
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
            TotalSize = dto.TotalSize,
            ContentType = dto.ContentType,
            ChunkSize = dto.ChunkSize,
            CryptoVersion = dto.CryptoVersion,
            ManifestBlobPath = manifestPath,
            UploadedAt = DateTime.UtcNow,
            FileEncryptionVersion = 1
        };

        var key = new FileKey
        {
            FileRecordId = fileId,
            WrappedFileKey = dto.WrappedFileKey
        };

        _db.FileAccesses.Add(new FileAccessEntity
        {
            Id = Guid.NewGuid(),
            FileRecordId = fileId,
            UserId = userId,
            WrappedDek = dto.WrappedFileKey,
            Permissions = "owner",
            KeyVersion = 1,
            FileEncryptionVersion = record.FileEncryptionVersion,
            CreatedAt = DateTime.UtcNow,
            RevokedAt = null
        });

        _db.Files.Add(record);
        _db.FileKeys.Add(key);
        await _db.SaveChangesAsync();

        return Ok(new { fileId });
    }

    // ---------------- UPLOAD CHUNK ----------------
    [HttpPut("{id:guid}/chunks/{index:int}")]
    public async Task<IActionResult> UploadChunk(Guid id, int index)
    {
        var record = await GetFileIfAuthorized(id);
        if (record == null) return Forbid();

        await _blob.PutChunkAsync(id, index, Request.Body);
        return Ok();
    }

    // ---------------- DIRECT UPLOAD ----------------
    [HttpPost("upload")]
    public async Task<IActionResult> Upload([FromForm] UploadFileRequest request, CancellationToken ct)
    {
        var userId = User.GetUserId();
        if (userId == Guid.Empty) return Unauthorized();

        if (request.File == null) return BadRequest("No file uploaded");

        var fileId = await _fileStore.SaveAsync(userId, request.File, ct);
        return Ok(new { fileId });
    }

    // ---------------- COMPLETE UPLOAD ----------------
    [HttpPost("{id:guid}/complete")]
    public async Task<IActionResult> Complete(Guid id)
    {
        var record = await GetFileIfAuthorized(id);
        if (record == null) return Forbid();

        return Ok(new { status = "Completed", fileId = id });
    }

    // ---------------- LIST FILES ----------------
    [HttpGet]
    public async Task<IActionResult> List()
    {
        var userId = User.GetUserId();
        var files = await _fileStore.ListAsync(userId);

        var dtos = files.Select(f => new FileMetadataDto
        {
            Id = f.Id,
            FileName = f.EncryptedFileName,
            ContentType = f.ContentType,
            Length = f.TotalSize,
            UploadedAt = f.UploadedAt,
            CryptoVersion = f.CryptoVersion,
            WrappedKeys = f.Keys.Select(k => k.WrappedFileKey).ToList(),
            EncryptedVersion = f.FileEncryptionVersion
        });

        return Ok(dtos);
    }

    // ---------------- GET METADATA ----------------
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetMetadata(Guid id)
    {
        var record = await GetFileIfAuthorized(id);
        if (record == null) return Forbid();

        var dto = new FileMetadataDto
        {
            Id = record.Id,
            FileName = record.EncryptedFileName,
            ContentType = record.ContentType,
            Length = record.TotalSize,
            UploadedAt = record.UploadedAt,
            CryptoVersion = record.CryptoVersion,
            WrappedKeys = record.Keys.Select(k => k.WrappedFileKey).ToList(),
            EncryptedVersion = record.FileEncryptionVersion
        };

        return Ok(dto);
    }

    // ---------------- GET MANIFEST ----------------
    [HttpGet("{id:guid}/manifest")]
    public async Task<IActionResult> GetManifest(Guid id)
    {
        var record = await GetFileIfAuthorized(id);
        if (record == null) return Forbid();

        var stream = await _blob.GetManifestAsync(id);
        if (stream == null) return NotFound("Manifest not found");

        return File(stream, "application/octet-stream", "manifest");
    }

    // ---------------- GET CHUNK ----------------
    [HttpGet("{id:guid}/chunks/{index:int}")]
    public async Task<IActionResult> GetChunk(Guid id, int index)
    {
        var record = await GetFileIfAuthorized(id);
        if (record == null) return Forbid();

        var stream = await _blob.GetChunkAsync(id, index);
        if (stream == null) return NotFound("Chunk not found");

        return File(stream, "application/octet-stream", $"chunk_{index}");
    }

    // ---------------- DOWNLOAD FULL FILE ----------------
    [HttpGet("{id:guid}/download")]
    public async Task<IActionResult> Download(Guid id)
    {
        var record = await GetFileIfAuthorized(id);
        if (record == null) return Forbid();

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

    // ---------------- GET WRAPPED DEK ----------------
    [HttpGet("{id:guid}/key")]
    public async Task<IActionResult> GetFileKey(Guid id)
    {
        var userId = User.GetUserId();

        var file = await _db.Files.FindAsync(id);
        if (file == null) return NotFound();

        var access = await _db.FileAccesses.FirstOrDefaultAsync(f =>
            f.FileRecordId == id &&
            f.UserId == userId &&
            f.FileEncryptionVersion == file.FileEncryptionVersion &&
            f.RevokedAt == null);

        if (access != null)
        {
            return Ok(new
            {
                wrappedDek = access.WrappedDek,
                keyVersion = access.KeyVersion,
                encryptedVersion = access.FileEncryptionVersion
            });
        }

        return Forbid();
    }

    // ---------------- ROTATE KEYS ----------------
    [HttpPost("{id:guid}/rotate")]
    public async Task<IActionResult> Rotate(Guid id, [FromBody] RotateRequest request)
    {
        var userId = User.GetUserId();

        var isOwner = await _db.FileAccesses.AnyAsync(f =>
            f.FileRecordId == id &&
            f.UserId == userId &&
            f.Permissions == "owner" &&
            f.RevokedAt == null);

        if (!isOwner)
            return Forbid();

        var file = await _db.Files.FindAsync(id);
        if (file == null)
            return NotFound();

        file.FileEncryptionVersion++;
        var newVersion = file.FileEncryptionVersion;

        foreach (var member in request.Members)
        {
            _db.FileAccesses.Add(new FileAccessEntity
            {
                Id = Guid.NewGuid(),
                FileRecordId = id,
                UserId = member.UserId,
                WrappedDek = member.WrappedDek,
                Permissions = "read",
                KeyVersion = member.KeyVersion,
                FileEncryptionVersion = newVersion,
                CreatedAt = DateTime.UtcNow
            });
        }

        await _db.SaveChangesAsync();

        return Ok(new
        {
            message = "File rotated successfully",
            version = newVersion
        });
    }

    // ---------------- DTOs ----------------
    public class RotateRequest
    {
        public List<RotateMember> Members { get; set; } = new();
    }

    public class RotateMember
    {
        public Guid UserId { get; set; }
        public string WrappedDek { get; set; } = null!;
        public int KeyVersion { get; set; }
    }
}