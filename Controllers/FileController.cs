using System.Security.Claims;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure;
using FileFox_Backend.Infrastructure.Extensions;
using FileFox_Backend.Infrastructure.Services;
using FileFox_Backend.Infrastructure.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

using FileFox_Backend.Core.Interfaces;
using FileFox_Backend.Infrastructure.Results;
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
            UploadedAt = DateTime.UtcNow
        };

        var key = new FileKey
        {
            FileRecordId = fileId,
            WrappedFileKey = dto.WrappedFileKey
        };

        _db.Files.Add(record);
        _db.FileKeys.Add(key);
        await _db.SaveChangesAsync();

        return Ok(new { fileId });
    }

    // ---------------- UPLOAD CHUNK ----------------
    [HttpPut("{id:guid}/chunks/{index:int}")]
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
        var userId = User.GetUserId();
        var record = await _db.Files.FirstOrDefaultAsync(f => f.Id == id && f.UserId == userId);

        if (record == null) return NotFound();

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
            WrappedKeys = f.Keys.Select(k => k.WrappedFileKey).ToList()
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
            .FirstOrDefaultAsync(f => f.Id == id && f.UserId == userId);

        if (record == null) return NotFound();

        var dto = new FileMetadataDto
        {
            Id = record.Id,
            FileName = record.EncryptedFileName,
            ContentType = record.ContentType,
            Length = record.TotalSize,
            UploadedAt = record.UploadedAt,
            CryptoVersion = record.CryptoVersion,
            WrappedKeys = record.Keys.Select(k => k.WrappedFileKey).ToList()
        };

        return Ok(dto);
    }

    // ---------------- GET MANIFEST ----------------
    [HttpGet("{id:guid}/manifest")]
    public async Task<IActionResult> GetManifest(Guid id)
    {
        var userId = User.GetUserId();
        var record = await _db.Files.FirstOrDefaultAsync(f => f.Id == id && f.UserId == userId);
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
        var record = await _db.Files.FirstOrDefaultAsync(f => f.Id == id && f.UserId == userId);
        if (record == null) return NotFound();

        var stream = await _blob.GetChunkAsync(id, index);
        if (stream == null) return NotFound("Chunk not found");

        return File(stream, "application/octet-stream", $"chunk_{index}");
    }

    // ---------------- DOWNLOAD FULL FILE ----------------
    [HttpGet("{id:guid}/download")]
    public async Task<IActionResult> Download(Guid id)
    {
        var userId = User.GetUserId();
        var record = await _db.Files.FirstOrDefaultAsync(f => f.Id == id && f.UserId == userId);

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
}