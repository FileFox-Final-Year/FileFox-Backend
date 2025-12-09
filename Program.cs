using FileFox_Backend.Data;
using FileFox_Backend.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Add controllers so we can have API endpoints
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
// Add Swagger for API documentation and testing
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", new OpenApiInfo { Title = "FileFox API", Version = "v1" });

    o.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header. Example: Bearer {token}",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });

    o.AddSecurityRequirement(new OpenApiSecurityRequirement
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
            new string[] {}
        }
    });
});

// Database configuration
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// EF core user store (database-backed user storage)
builder.Services.AddScoped<IUserStore, EFCoreUserStore>();
// EF core file store (database-backed file storage)
builder.Services.AddScoped<IFileStore, EFCoreFileStore>();
// Token service for generating JWTs
builder.Services.AddScoped<ITokenService, JwtTokenService>();
builder.Services.AddScoped<RefreshTokenService>();

// Configure JWT authentication
var key = Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? "JWTSecretKey1234567890");
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),

            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],

            ValidateAudience = true,
            ValidAudience = builder.Configuration["Jwt:Audience"],

            RequireExpirationTime = true,
            ValidateLifetime = true,

            ClockSkew = TimeSpan.FromMinutes(1)
        };
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
// Enable Swagger middleware for API documentation
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "FileFox API v1");
});


app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
