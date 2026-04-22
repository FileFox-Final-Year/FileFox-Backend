using System;
using System.Linq;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using FileFox_Backend.Infrastructure.Data;

namespace FileFox_Backend.Tests;

public class TestWebApplicationFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureServices(services =>
        {
            var dbDescriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));

            if (dbDescriptor != null)
                services.Remove(dbDescriptor);

            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseInMemoryDatabase("FileFoxMemoryDb");
            });

            services.AddRateLimiter(options =>
            {
                // Completely disable rate limiting in tests
                options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ =>
                    RateLimitPartition.GetNoLimiter("test"));

                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

                // Add all rate limiting policies with no limits for testing
                options.AddPolicy("AuthLimiter", _ => RateLimitPartition.GetNoLimiter("test"));
                options.AddPolicy("FileLimiter", _ => RateLimitPartition.GetNoLimiter("test"));
                options.AddPolicy("MfaLimiter", _ => RateLimitPartition.GetNoLimiter("test"));
                options.AddPolicy("KeyLimiter", _ => RateLimitPartition.GetNoLimiter("test"));
                options.AddPolicy("ShareLimiter", _ => RateLimitPartition.GetNoLimiter("test"));
            });
        });
    }
}