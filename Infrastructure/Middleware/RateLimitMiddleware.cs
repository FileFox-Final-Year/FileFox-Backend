using System.Collections.Concurrent;

namespace FileFox_Backend.Infrastructure.Middleware;

public class RateLimitMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RateLimitMiddleware> _logger;
    private readonly ConcurrentDictionary<string, RateLimitBucket> _buckets = new();
    
    // Configuration: endpoint -> (requestsPerMinute)
    private readonly Dictionary<string, int> _endpointLimits = new()
    {
        { "/auth/register", 3 },
        { "/auth/login", 5 },
        { "/auth/login/mfa", 5 },
        { "/files/share", 10 },
    };

    public RateLimitMiddleware(RequestDelegate next, ILogger<RateLimitMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";
        var method = context.Request.Method;

        // Only rate limit POST/DELETE requests on specific endpoints
        if ((method == "POST" || method == "DELETE") && IsRateLimitedEndpoint(path, out var limit))
        {
            var clientId = GetClientIdentifier(context);
            var key = $"{clientId}:{path}";

            if (!IsRequestAllowed(key, limit))
            {
                _logger.LogWarning($"Rate limit exceeded for {clientId} on {path}");
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                await context.Response.WriteAsJsonAsync(new { error = "Too many requests. Please try again later." });
                return;
            }
        }

        await _next(context);
    }

    private bool IsRateLimitedEndpoint(string path, out int limit)
    {
        limit = 0;
        foreach (var (endpoint, requestLimit) in _endpointLimits)
        {
            if (path.StartsWith(endpoint, StringComparison.OrdinalIgnoreCase))
            {
                limit = requestLimit;
                return true;
            }
        }
        return false;
    }

    private string GetClientIdentifier(HttpContext context)
    {
        // Try to get user ID from claims first (for authenticated requests)
        var userId = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (!string.IsNullOrEmpty(userId))
            return $"user_{userId}";

        // Fall back to IP address
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return $"ip_{ip}";
    }

    private bool IsRequestAllowed(string key, int requestsPerMinute)
    {
        var now = DateTimeOffset.UtcNow;
        
        var bucket = _buckets.AddOrUpdate(key,
            _ => new RateLimitBucket { ResetTime = now.AddMinutes(1), Count = 1 },
            (_, existing) =>
            {
                // Reset bucket if time window has passed
                if (now > existing.ResetTime)
                {
                    existing.Count = 1;
                    existing.ResetTime = now.AddMinutes(1);
                }
                else
                {
                    existing.Count++;
                }
                return existing;
            });

        return bucket.Count <= requestsPerMinute;
    }

    private class RateLimitBucket
    {
        public int Count { get; set; }
        public DateTimeOffset ResetTime { get; set; }
    }
}

public static class RateLimitMiddlewareExtensions
{
    public static IApplicationBuilder UseRateLimiting(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<RateLimitMiddleware>();
    }
}
