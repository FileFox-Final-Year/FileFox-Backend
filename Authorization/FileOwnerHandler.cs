using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using FileFox_Backend.Models;

namespace FileFox_Backend.Authorization
{
    public class FileOwnerHandler
        : AuthorizationHandler<FileOwnerRequirement, FileRecord>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            FileOwnerRequirement requirement,
            FileRecord fileRecord)
        {
            if (fileRecord == null)
                return Task.CompletedTask;

            // Get user ID from JWT
            var userIdClaim =
                context.User.FindFirst(ClaimTypes.NameIdentifier)
                ?? context.User.FindFirst("sub");

            if (userIdClaim == null)
                return Task.CompletedTask;

            if (!Guid.TryParse(userIdClaim.Value, out var userId))
                return Task.CompletedTask;

            // OWNER CHECK
            if (fileRecord.UserId == userId)
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }

            // ADMIN OVERRIDE
            if (context.User.IsInRole("Admin"))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
