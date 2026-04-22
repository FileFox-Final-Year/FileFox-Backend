using FileFox_Backend.Core.Interfaces;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Data;
using FileFox_Backend.Infrastructure.Services;
using FileFox_Backend.Infrastructure.Middleware;
using FileFox_Backend.Infrastructure.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

// -------------------- SECRET PROVIDER --------------------
builder.Services.AddSingleton<ISecretProvider, LocalSecretProvider>();

// -------------------- DATABASE --------------------
if (builder.Environment.IsEnvironment("Testing"))
{
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
        options.UseInMemoryDatabase("FileFoxMemoryDb"));
}
else
{
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlServer(builder.Configuration.GetConnectionString("Default")));
}

// -------------------- SERVICES --------------------
builder.Services.AddScoped<IUserStore, EFCoreUserStore>();
builder.Services.AddScoped<ITokenService, JwtTokenService>();
builder.Services.AddScoped<RefreshTokenService>();
builder.Services.AddScoped<IBlobStorageService, LocalBlobStorage>();
builder.Services.AddScoped<IFileStore, LocalFileStore>();
builder.Services.AddScoped<FileService>();
builder.Services.AddScoped<IRecoveryCodeService, RecoveryCodeService>();
builder.Services.AddScoped<IAuthorizationHandler, FileOwnerHandler>();
builder.Services.AddScoped<AuditService>();
builder.Services.AddScoped<ManifestService>();
builder.Services.AddScoped<IFileAuthorizationService, FileAuthorizationService>();

// -------------------- RATE LIMITING --------------------
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    if (builder.Environment.IsEnvironment("Testing"))
    {
        options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ =>
            RateLimitPartition.GetNoLimiter("test"));
        return;
    }

    options.AddPolicy("AuthLimiter", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.User.Identity?.Name
                ?? context.Connection.RemoteIpAddress?.ToString()
                ?? "anonymous",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));

    options.AddPolicy("FileLimiter", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.User.Identity?.Name
                ?? context.Connection.RemoteIpAddress?.ToString()
                ?? "anonymous",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));

    options.AddPolicy("MfaLimiter", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.User.Identity?.Name
                ?? context.Connection.RemoteIpAddress?.ToString()
                ?? "anonymous",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 3,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));

    options.AddPolicy("KeyLimiter", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.User.Identity?.Name
                ?? context.Connection.RemoteIpAddress?.ToString()
                ?? "anonymous",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));

    options.AddPolicy("ShareLimiter", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.User.Identity?.Name
                ?? context.Connection.RemoteIpAddress?.ToString()
                ?? "anonymous",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 20,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
});

builder.Services.AddControllers();

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin() // Change to frontend URL in production
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// -------------------- AUTHORIZATION --------------------
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("User"));
    options.AddPolicy("FileOwnerPolicy", policy =>
        policy.Requirements.Add(new FileOwnerRequirement()));
});

// -------------------- AUTHENTICATION --------------------
var jwtConfig = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtConfig["Key"]!);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,

        ValidIssuer = jwtConfig["Issuer"],
        ValidAudience = jwtConfig["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(key),

        ClockSkew = TimeSpan.FromMinutes(5),

        RoleClaimType = ClaimTypes.Role,
        NameClaimType = JwtRegisteredClaimNames.Sub
    };
});

// -------------------- SWAGGER --------------------
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: 'abc123token'",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// -------------------- ERROR HANDLING --------------------
app.UseMiddleware<GlobalExceptionMiddleware>();

// -------------------- HTTPS + HSTS --------------------
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseHttpsRedirection();

// -------------------- ROUTING --------------------
app.UseRouting();

// -------------------- CORS --------------------
app.UseCors(policy =>
{
    policy.WithOrigins("http://localhost:3000") // change to frontend URL
          .AllowAnyHeader()
          .AllowAnyMethod();
});

// -------------------- SECURITY HEADERS --------------------
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Permissions-Policy"] = "geolocation=()";

    await next();
});

// -------------------- RATE LIMITING --------------------
app.UseRateLimiter();

// -------------------- AUTH --------------------
app.UseAuthentication();
app.UseAuthorization();

// -------------------- HEALTH CHECK --------------------
app.MapGet("/health", () => Results.Ok("OK"));

// -------------------- ENDPOINTS --------------------
app.MapControllers();

app.Run();

public partial class Program { }