using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Data;
using FileFox_Backend.Infrastructure.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace FileFox_Backend.Controllers;

[ApiController]
[Route("files")]
[Authorize]
public class ShareController : ControllerBase
{
    private readonly ApplicationDbContext _dbContext;

    public ShareController(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

// ---------------- SHARE FILE ----------------
    [HttpPost("{fileId:guid}/share")]
    public async Task<IActionResult> ShareFile(Guid fileId, [FromBody] ShareRequest request)
     {
        var userId = User.GetUserId();

        // Check ownership via FileAccess (NOT FileRecord)
        var isOwner = await _dbContext.FileAccesses.AnyAsync(f =>
            f.FileRecordId == fileId &&
            f.UserId == userId &&
            f.Permissions == "owner" &&
            f.RevokedAt == null);

        if (!isOwner)
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
            existing.RevokedAt = null; // reactivate if previously revoked
        }
        else
        {
            _dbContext.FileAccesses.Add(new Core.Models.FileAccess
            {
                Id = Guid.NewGuid(),
                FileRecordId = fileId,
                UserId = request.RecipientUserId,
                WrappedDek = request.WrappedDek,
                Permissions = request.Permissions ?? "read",
                KeyVersion = request.KeyVersion,
                CreatedAt = DateTime.UtcNow,
                RevokedAt = null
            });
        }

        await _dbContext.SaveChangesAsync();

        return Ok(new { message = "File shared successfully" });
    }

// ---------------- REVOKE SHARE ----------------
    [HttpDelete("{fileId:guid}/share/{recipientUserId:guid}")]
    public async Task<IActionResult> RevokeShare(Guid fileId, Guid recipientUserId)
    {
        var userId = User.GetUserId();

        // Only owner can revoke
        var isOwner = await _dbContext.FileAccesses.AnyAsync(f =>
            f.FileRecordId == fileId &&
            f.UserId == userId &&
            f.Permissions == "owner" &&
            f.RevokedAt == null);

        if (!isOwner)
            return Forbid();

        var access = await _dbContext.FileAccesses.FirstOrDefaultAsync(a =>
            a.FileRecordId == fileId &&
            a.UserId == recipientUserId &&
            a.RevokedAt == null);

        if (access == null)
            return NotFound(new { error = "Share record not found" });

        access.RevokedAt = DateTime.UtcNow;

        await _dbContext.SaveChangesAsync();

        return Ok(new { message = "Share revoked" });
    }

    [HttpGet("{fileId:guid}/shares")]
    public async Task<IActionResult> GetShares(Guid fileId)
    {
        var userId = User.GetUserId();

        // Only owner can view shares
        var isOwner = await _dbContext.FileAccesses.AnyAsync(f =>
            f.FileRecordId == fileId &&
            f.UserId == userId &&
            f.Permissions == "owner" &&
            f.RevokedAt == null);

        if (!isOwner)
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
