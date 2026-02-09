using System.Security.Claims;

namespace FileFox_Backend.Extensions;

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