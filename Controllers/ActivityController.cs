using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Extensions;
using FileFox_Backend.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FileFox_Backend.Controllers;

[ApiController]
[Route("activity")]
[Authorize]
public class ActivityController : ControllerBase
{
    private readonly AuditService _audit;

    public ActivityController(AuditService audit)
    {
        _audit = audit;
    }

    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var userId = User.GetUserId();
        var logs = await _audit.GetLogsForUserAsync(userId);

        var result = logs.Select(l => new
        {
            id = l.Id.ToString(),
            title = l.Action,
            message = GetMessage(l),
            time = FormatTimestamp(l.Timestamp)
        });

        return Ok(result);
    }

    private static string GetMessage(AuditLog log)
    {
        if (log.FileRecordId.HasValue)
        {
            return $"Related to file: {log.FileRecordId.Value.ToString()[..8]}...";
        }

        return "Account security event";
    }

    private static string FormatTimestamp(DateTimeOffset timestamp)
    {
        var now = DateTimeOffset.UtcNow;
        var diff = now - timestamp;

        if (diff.TotalMinutes < 1) return "Just now";
        if (diff.TotalHours < 1) return $"{(int)diff.TotalMinutes}m ago";
        if (diff.TotalDays < 1) return $"{(int)diff.TotalHours}h ago";
        if (diff.TotalDays < 7) return $"{(int)diff.TotalDays}d ago";

        return timestamp.ToString("MMM dd, yyyy");
    }
}
