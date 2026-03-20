using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using FileFox_Backend.Core.Models;

using FileFox_Backend.Core.Interfaces;
namespace FileFox_Backend.Infrastructure.Authorization
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

            var userIdClaim = 
                context.User.FindFirst(ClaimTypes.NameIdentifier)
                ?? context.User.FindFirst("sub");

            if (userIdClaim == null || !Guid.TryParse(userIdClaim.Value, out var userId))
                return Task.CompletedTask;

            if (fileRecord.UserId == userId || context.User.IsInRole("Admin"))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}