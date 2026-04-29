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
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// -------------------- SERVICES --------------------
builder.Services.AddScoped<IUserStore, EFCoreUserStore>();
builder.Services.AddScoped<ITokenService, JwtTokenService>();
builder.Services.AddScoped<RefreshTokenService>();
builder.Services.AddScoped<IBlobStorageService, SqlBlobStorage>();
builder.Services.AddScoped<IFileStore, DbFileStore>();
builder.Services.AddScoped<FileService>();
builder.Services.AddScoped<AuditService>();
builder.Services.AddScoped<IAuthorizationHandler, FileOwnerHandler>();

builder.Services.AddControllers();

// -------------------- RATE LIMITING --------------------
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddFixedWindowLimiter("api", opt =>
    {
        opt.Window = TimeSpan.FromMinutes(1);
        opt.PermitLimit = 100;
        opt.QueueLimit = 0;
    });

    options.AddFixedWindowLimiter("auth", opt =>
    {
        opt.Window = TimeSpan.FromMinutes(1);
        opt.PermitLimit = 10;
        opt.QueueLimit = 0;
    });
});

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
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

// -------------------- DATABASE AUTO-MIGRATION/CREATION --------------------
using (var scope = app.Services.CreateScope())
{
    var config = scope.ServiceProvider.GetRequiredService<IConfiguration>();
    var connectionString = config.GetConnectionString("DefaultConnection");

    if (string.IsNullOrWhiteSpace(connectionString) || connectionString.Contains("YOUR_AWS_RDS_ENDPOINT"))
    {
        Console.WriteLine("********************************************************************************");
        Console.WriteLine("ERROR: Database Connection String is not configured.");
        Console.WriteLine("Please update 'DefaultConnection' in appsettings.json with your AWS RDS details.");
        Console.WriteLine("Refer to the README.md for setup instructions.");
        Console.WriteLine("********************************************************************************");
        // In a real production app, we might just log this, but for a dev-ready project,
        // stopping early with a clear message is helpful.
        return;
    }

    try
    {
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        db.Database.EnsureCreated();

        // Self-healing: Ensure AuditLogs.FileRecordId is nullable in case it was created NOT NULL
        try {
            db.Database.ExecuteSqlRaw("ALTER TABLE AuditLogs ALTER COLUMN FileRecordId UNIQUEIDENTIFIER NULL");
        } catch { /* Table might not exist or column already nullable */ }
    }
    catch (Exception ex)
    {
        Console.WriteLine("********************************************************************************");
        Console.WriteLine("ERROR: Could not connect to the database.");
        Console.WriteLine($"Message: {ex.Message}");
        Console.WriteLine();
        Console.WriteLine("Troubleshooting steps:");
        Console.WriteLine("1. Verify your connection string in appsettings.json.");
        Console.WriteLine("2. Ensure your AWS RDS instance is running.");
        Console.WriteLine("3. Check AWS Security Groups to allow port 1433 from your IP.");
        Console.WriteLine("4. Ensure 'TrustServerCertificate=True' is in your connection string.");
        Console.WriteLine("********************************************************************************");
        return;
    }
}

// -------------------- MIDDLEWARE --------------------
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseMiddleware<GlobalExceptionMiddleware>();
app.UseMiddleware<SecurityHeadersMiddleware>();

// app.UseHttpsRedirection();

app.UseCors();

app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
public partial class Program { }
