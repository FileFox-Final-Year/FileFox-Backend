﻿using System;
using System.Threading.Tasks;
using FileFox_Backend.Core.Interfaces;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Data;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Xunit;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;


namespace FileFox_Backend.Tests;

public class AuthTests
{
    private ApplicationDbContext GetInMemoryDb()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new ApplicationDbContext(options);
    }

    private EFCoreUserStore GetUserStore(ApplicationDbContext db) => new EFCoreUserStore(db);
    private JwtTokenService GetJwtTokenService()
    {
        var secretProvider = new TestSecretProvider();
        return new JwtTokenService(secretProvider);
    }

    [Fact]
    public async Task Register_Login_Refresh_Success()
    {
        using var db = GetInMemoryDb();
        var userStore = GetUserStore(db);

        var (created, user, error) = await userStore.RegisterAsync("testuser", "test@example.com", "password123");
        Assert.True(created);
        Assert.NotNull(user);
        Assert.Null(error);

        var loggedIn = await userStore.ValidateCredentialsAsync("test@example.com", "password123");
        Assert.NotNull(loggedIn);
        Assert.Equal(user!.Id, loggedIn!.Id);
    }

    [Fact]
    public async Task Invalid_Login_Fails()
    {
        using var db = GetInMemoryDb();
        var userStore = GetUserStore(db);

        await userStore.RegisterAsync("testuser", "test@example.com", "password123");

        var invalidPassword = await userStore.ValidateCredentialsAsync("test@example.com", "wrongpassword");
        Assert.Null(invalidPassword);

        var invalidEmail = await userStore.ValidateCredentialsAsync("wrong@example.com", "password123");
        Assert.Null(invalidEmail);
    }

    [Fact]
    public async Task Duplicate_Registration_Fails()
    {
        using var db = GetInMemoryDb();
        var userStore = GetUserStore(db);

        await userStore.RegisterAsync("user1", "duplicate@example.com", "Password123!");
        var (created, _, error) = await userStore.RegisterAsync("user2", "duplicate@example.com", "Password123!");

        Assert.False(created);
        Assert.Equal("User already exists", error);
    }

    [Fact]
    public void MfaToken_Creation_And_Validation_Succeeds()
    {
        var secretProvider = new TestSecretProvider();
        var jwtService = new JwtTokenService(secretProvider);

        var user = new User
        {
            Id = Guid.NewGuid(),
            UserName = "mfauser",
            Email = "mfauser@example.com",
            PasswordHash = "dummyhash",
            Role = "User"
        };

        // create MFA token
        var mfaToken = jwtService.CreateMfaToken(user);
        Assert.False(string.IsNullOrEmpty(mfaToken));

        // validate MFA token
        var principal = jwtService.ValidateMfaToken(mfaToken);
        Assert.NotNull(principal);

        // principal contains correct user info
        Assert.Equal(user.Id.ToString(), principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value);
        Assert.Equal("mfa", principal.FindFirst("typ")?.Value);
    }

    [Fact]
    public void ValidateMfaToken_Fails_When_TokenIsNotMfa()
    {
        var jwtService = new JwtTokenService(new TestSecretProvider());

        var user = new User
        {
            Id = Guid.NewGuid(),
            UserName = "regularuser",
            Email = "regularuser@example.com",
            PasswordHash = "dummyhash",
            Role = "User"
        };

        // create a NORMAL access token
        var accessToken = jwtService.CreateToken(user);

        // try to validate it as MFA token
        var principal = jwtService.ValidateMfaToken(accessToken);

        Assert.Null(principal);
    }

    [Fact]
    public void ValidateMfaToken_Fails_When_Expired()
    {
        var jwtService = new JwtTokenService(new TestSecretProvider());

        var user = new User
        {
            Id = Guid.NewGuid(),
            UserName = "expireduser",
            Email = "expireduser@example.com",
            PasswordHash = "dummyhash",
            Role = "User"
        };

        // manually create expired token
        var handler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes("ThisIsATestKeyThatIsDefinitelyLongEnough123!");

        var token = handler.CreateJwtSecurityToken(
            issuer: "FileFoxDev",
            audience: "FileFoxDevAudience",
            subject: new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim("typ", "mfa")
            }),
            notBefore: DateTime.UtcNow.AddMinutes(-10),
            expires: DateTime.UtcNow.AddMinutes(-5),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256)
        );

        var expiredToken = handler.WriteToken(token);

        var principal = jwtService.ValidateMfaToken(expiredToken);

        Assert.Null(principal);
    }

    [Fact]
    public async Task RefreshToken_Fails_When_UserDeleted()
    {
        using var db = GetInMemoryDb();
        var userStore = GetUserStore(db);

        var (created, user, _) = await userStore.RegisterAsync(
            "refreshuser",
            "refresh@example.com",
            "Password123!");

        db.Users.Remove(user!);
        await db.SaveChangesAsync();

        var refreshed = await userStore.ValidateCredentialsAsync(
            "refresh@example.com",
            "Password123!");

        Assert.Null(refreshed);
    }

    [Fact]
    public void ValidateMfaToken_Fails_When_TokenIsTampered()
    {
        var jwtService = new JwtTokenService(new TestSecretProvider());

        var user = new User
        {
            Id = Guid.NewGuid(),
            UserName = "tampereduser",
            Email = "tampereduser@example.com",
            PasswordHash = "dummyhash",
            Role = "User"
        };

        var token = jwtService.CreateMfaToken(user);

        // tamper with token
        var tampered = token.Replace("a", "b");

        var principal = jwtService.ValidateMfaToken(tampered);

        Assert.Null(principal);
    }

    [Fact]
    public async Task Login_With_MfaEnabled_DoesNotReturnAccessToken()
    {
        using var db = GetInMemoryDb();
        var userStore = GetUserStore(db);

        var (created, user, _) = await userStore.RegisterAsync(
            "mfauser",
            "mfa@example.com",
            "Password123!");

        user!.MfaEnabled = true;
        await db.SaveChangesAsync();

        var loginUser = await userStore.ValidateCredentialsAsync(
            "mfa@example.com",
            "Password123!");

        Assert.NotNull(loginUser);
        Assert.True(loginUser!.MfaEnabled);
    }

    public class TestSecretProvider : ISecretProvider
    {
        public string GetSecret(string key)
        {
            return "ThisIsATestKeyThatIsDefinitelyLongEnough123!";
        }
    }
}