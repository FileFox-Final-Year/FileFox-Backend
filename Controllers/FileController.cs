using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Extensions;
using FileFox_Backend.Infrastructure.Data;
using FileFox_Backend.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.RateLimiting;
using FileFox_Backend.Infrastructure.Results;
using FileAccessEntity = FileFox_Backend.Core.Models.FileAccess;
namespace FileFox_Backend.Controllers;

[ApiController]
[Route("files")]
[Authorize]
[EnableRateLimiting("FileLimiter")]
public class FilesController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IBlobStorageService _blob;
    private readonly IFileStore _fileStore;
    private readonly AuditService _auditService;
    private readonly ManifestService _manifestService;
    private readonly FileAuthorizationService _authService;

    public FilesController(ApplicationDbContext db, IBlobStorageService blob, IFileStore fileStore, AuditService auditService, ManifestService manifestService, FileAuthorizationService fileAuthorizationService)
    {
        _db = db;
        _blob = blob;
        _fileStore = fileStore;
        _auditService = auditService;
        _manifestService = manifestService;
        _authService = fileAuthorizationService;
    }
    
    // ---------------- AUTH HELPER ----------------
    private async Task<FileRecord?> GetFileIfAuthorized(Guid fileId)
    {
        var userId = User.GetUserId();

        var hasAccess = await _db.FileAccesses.AnyAsync(a =>
            a.FileRecordId == fileId &&
            a.UserId == userId &&
            a.RevokedAt == null);

        if (!hasAccess)
            return null;

        return await _db.Files
            .Include(f => f.Keys)
            .FirstOrDefaultAsync(f => f.Id == fileId);
    }

     // ---------------- INIT UPLOAD ----------------
    [HttpPost("init")]
    public async Task<IActionResult> Init([FromBody] InitUploadDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.EncryptedManifestHeader))
            return BadRequest("Manifest header required");
        
        try{
            Convert.FromBase64String(dto.EncryptedManifestHeader);}
        catch{
            return BadRequest("Manifest header must be valid Base64");}

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
            EncryptedFolderPath = dto.EncryptedFolderPath,
            MetadataVersion = dto.MetadataVersion,
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

        // Audit log: file upload initiated
        await _auditService.LogFileActionAsync(userId, fileId, "FILE_UPLOAD_INITIATED");

        return Ok(new { fileId });
    }

    // ---------------- UPLOAD CHUNK ----------------
    [HttpPut("{id:guid}/chunks/{index:int}")]
    public async Task<IActionResult> UploadChunk(Guid id, int index)
    {
        var record = await GetFileIfAuthorized(id);
        if (record == null) return Forbid();

        await _blob.PutChunkAsync(id, index, Request.Body);

        // Audit log: chunk uploaded
        var userId = User.GetUserId();
        await _auditService.LogFileActionAsync(userId, id, $"FILE_CHUNK_UPLOADED_INDEX_{index}");

        return Ok();
    }

    // ---------------- COMPLETE UPLOAD ----------------
    [HttpPost("{id:guid}/complete")]
    public async Task<IActionResult> Complete(Guid id)
    {
        var record = await GetFileIfAuthorized(id);
        if (record == null) return Forbid();

        // Audit log: file upload completed
        var userId = User.GetUserId();
        await _auditService.LogFileActionAsync(userId, id, "FILE_UPLOAD_COMPLETED");

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
            FolderPath = f.EncryptedFolderPath,
            MetadataVersion = f.MetadataVersion,
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
            FolderPath = record.EncryptedFolderPath,
            MetadataVersion = record.MetadataVersion,
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

        // Audit log: file download initiated
        var userId = User.GetUserId();
        await _auditService.LogFileActionAsync(userId, id, "FILE_DOWNLOAD_INITIATED");

        return new FileCallbackResult(
            record.ContentType ?? "application/octet-stream",
            async (outputStream, _) =>
            {
                int index = 0;

                while (true)
                {
                    var chunkStream = await _blob.GetChunkAsync(id, index);

                    if (chunkStream == null)
                        break;

                    await chunkStream.CopyToAsync(outputStream);

                    await chunkStream.DisposeAsync();

                    index++;
                }
            })
        {
            FileDownloadName = $"file-{id}"
        };
    }

    // ---------------- GET WRAPPED DEK ----------------
    [HttpGet("{id:guid}/key")]
    public async Task<IActionResult> GetFileKey(Guid id)
    {
        var userId = User.GetUserId();

        var file = await _db.Files.FindAsync(id);

        if (file == null)
            return NotFound();

        var access = await _db.FileAccesses.FirstOrDefaultAsync(f =>
            f.FileRecordId == id &&
            f.UserId == userId &&
            f.FileEncryptionVersion == file.FileEncryptionVersion &&
            f.RevokedAt == null);

        if (access == null)
            return Forbid();

        return Ok(new
        {
            wrappedDek = access.WrappedDek,
            keyVersion = access.KeyVersion,
            encryptedVersion = access.FileEncryptionVersion
        });
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

    // ---------------- VERIFY MANIFEST INTEGRITY ----------------
    [HttpPost("{id:guid}/verify-integrity")]
    public async Task<IActionResult> VerifyIntegrity(Guid id, [FromBody] VerifyIntegrityRequest request)
    {
        var record = await GetFileIfAuthorized(id);
        if (record == null) return Forbid();

        var userId = User.GetUserId();

        // Verify manifest hash is valid
        var isHashValid = _manifestService.VerifyManifestHash(request.ManifestHash, request.ChunkHashes);
        
        if (!isHashValid)
        {
            // Log integrity violation
            await _auditService.LogFileActionAsync(userId, id, "MANIFEST_INTEGRITY_VIOLATION_DETECTED");
            return BadRequest(new { error = "Manifest integrity verification failed", reason = "Hash mismatch" });
        }

        // Verify chunk sequence (no reordering, no drops)
        var isSequenceValid = _manifestService.VerifyChunkSequence(request.ChunkHashes.Count, request.AvailableChunkIndices);

        if (!isSequenceValid)
        {
            await _auditService.LogFileActionAsync(userId, id, "MANIFEST_CHUNK_SEQUENCE_VIOLATION_DETECTED");
            return BadRequest(new { error = "Manifest integrity verification failed", reason = "Chunk sequence violation (reorder/drop)" });
        }

        // Log successful verification
        await _auditService.LogFileActionAsync(userId, id, "MANIFEST_INTEGRITY_VERIFIED");

        var report = _manifestService.GenerateIntegrityReport(id, request.ChunkHashes.Count, request.ManifestHash, true);
        
        return Ok(new
        {
            verified = true,
            message = "Manifest integrity verified successfully",
            report
        });
    }

    // -------- DTOs --------
    public class VerifyIntegrityRequest
    {
        public string ManifestHash { get; set; } = null!;
        public List<string> ChunkHashes { get; set; } = new();
        public List<int> AvailableChunkIndices { get; set; } = new();
    }

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