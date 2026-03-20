using System.Security.Claims;

using FileFox_Backend.Core.Interfaces;
namespace FileFox_Backend.Infrastructure.Extensions;

public static class ClaimsPrincipalExtensions
{
    public static Guid GetUserId(this ClaimsPrincipal user)
    {
        var sub =
            user.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? user.FindFirstValue("sub");

        if (string.IsNullOrWhiteSpace(sub))
            throw new InvalidOperationException("User ID claim not found");

        return Guid.Parse(sub);
    }
}