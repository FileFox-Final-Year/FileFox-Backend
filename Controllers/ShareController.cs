using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Data;
using FileFox_Backend.Infrastructure.Extensions;
using FileFox_Backend.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using FileAccessEntity = FileFox_Backend.Core.Models.FileAccess;

namespace FileFox_Backend.Controllers;

[ApiController]
[Route("files/shares")]
[Authorize]
[EnableRateLimiting("ShareLimiter")]
public class ShareController : ControllerBase
{
    private readonly ApplicationDbContext _dbContext;
    private readonly FileAuthorizationService _authService;
    private readonly AuditService _auditService;

    public ShareController(ApplicationDbContext dbContext, FileAuthorizationService authService, AuditService auditService)
    {
        _dbContext = dbContext;
        _authService = authService;
        _auditService = auditService;
    }

// ---------------- SHARE FILE ----------------
    [HttpPost("{fileId:guid}/share")]
    public async Task<IActionResult> ShareFile(Guid fileId, [FromBody] ShareRequest request)
     {
        var userId = User.GetUserId();

        // Validate file exists
        var file = await _dbContext.Files.FindAsync(fileId);
        if (file == null)
            return NotFound();

        // Check ownership via FileAccess (NOT FileRecord)
        if (!await _authService.IsOwner(fileId, userId))
        return Forbid();

        // Validate recipient exists
        var recipientExists = await _dbContext.Users
            .AnyAsync(u => u.Id == request.RecipientUserId);

        if (!recipientExists)
            return BadRequest(new { error = "Recipient not found" });

        // Update and Insert FileAccess record
        var existing = await _dbContext.FileAccesses
            .FirstOrDefaultAsync(a =>
                a.FileRecordId == fileId &&
                a.UserId == request.RecipientUserId);

        if (existing != null)
        {
            existing.WrappedDek = request.WrappedDek;
            existing.Permissions = request.Permissions;
            existing.KeyVersion = request.KeyVersion;
            existing.FileEncryptionVersion = file.FileEncryptionVersion;
            existing.RevokedAt = null; // reactivate if previously revoked
        }
        else
        {
            _dbContext.FileAccesses.Add(new FileAccessEntity
            {
                Id = Guid.NewGuid(),
                FileRecordId = fileId,
                UserId = request.RecipientUserId,
                WrappedDek = request.WrappedDek,
                Permissions = request.Permissions ?? "read",
                KeyVersion = request.KeyVersion,
                FileEncryptionVersion = file.FileEncryptionVersion,
                CreatedAt = DateTime.UtcNow,
                RevokedAt = null
            });
        }

        await _dbContext.SaveChangesAsync();

        // Audit log: file shared with user
        await _auditService.LogFileActionAsync(userId, fileId, $"FILE_SHARED_WITH_USER_{request.RecipientUserId}");

        return Ok(new { message = "File shared successfully" });
    }

// ---------------- REVOKE SHARE ----------------
    [HttpDelete("{fileId:guid}/share/{recipientUserId:guid}")]
    public async Task<IActionResult> RevokeShare(Guid fileId, Guid recipientUserId)
    {
        var userId = User.GetUserId();

        // Only owner can revoke
        if (!await _authService.IsOwner(fileId, userId))
            return Forbid();

        var access = await _dbContext.FileAccesses.FirstOrDefaultAsync(a =>
            a.FileRecordId == fileId &&
            a.UserId == recipientUserId &&
            a.RevokedAt == null);

        if (access == null)
            return NotFound(new { error = "Share record not found" });

        access.RevokedAt = DateTime.UtcNow;

        await _dbContext.SaveChangesAsync();

        // Audit log: file share revoked
        await _auditService.LogFileActionAsync(userId, fileId, $"FILE_SHARE_REVOKED_FROM_USER_{recipientUserId}");

        return Ok(new { message = "Share revoked" });
    }

// ---------------- GET SHARES ----------------
    [HttpGet("{fileId:guid}/shares")]
    public async Task<IActionResult> GetShares(Guid fileId)
    {
        var userId = User.GetUserId();

        // Only owner can view shares
        if (!await _authService.IsOwner(fileId, userId))
            return Forbid();

        var shares = await _dbContext.FileAccesses
            .Where(f => f.FileRecordId == fileId && f.RevokedAt == null)
            .Select(f => new
            {
                f.UserId,
                f.Permissions,
                f.CreatedAt
            })
            .ToListAsync();

        return Ok(shares);
    }

    public class ShareRequest
    {
        public Guid RecipientUserId { get; set; }
        public string WrappedDek { get; set; } = null!;
        public string Permissions { get; set; } = "read";
        public int KeyVersion { get; set; } = 1;
    }
}
