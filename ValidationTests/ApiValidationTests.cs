using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Threading.Tasks;
using System.Linq;
using System;
using System.Collections.Generic;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Data;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Xunit;
using System.Text.Json;

namespace FileFox.ValidationTests;

public class ApiValidationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public ApiValidationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((context, config) =>
            {
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:DefaultConnection"] = "Server=localhost;Database=Test;User Id=sa;Password=Password123!;TrustServerCertificate=True"
                });
            });

            builder.ConfigureServices(services =>
            {
                var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
                if (descriptor != null) services.Remove(descriptor);

                services.AddDbContext<ApplicationDbContext>(options =>
                {
                    options.UseInMemoryDatabase("ValidationTestDb");
                });
            });
        });
    }

    private async Task<(HttpClient client, AuthResponse auth)> RegisterAndLogin(string username, string email, string password)
    {
        var client = _factory.CreateClient();

        // Register
        var regRes = await client.PostAsJsonAsync("/auth/register", new RegisterRequest { UserName = username, Email = email, Password = password });
        Assert.Equal(HttpStatusCode.Created, regRes.StatusCode);

        // Login
        var loginRes = await client.PostAsJsonAsync("/auth/login", new LoginRequest { Email = email, Password = password });
        Assert.Equal(HttpStatusCode.OK, loginRes.StatusCode);

        var loginData = await loginRes.Content.ReadFromJsonAsync<JsonElement>();
        string token = loginData.GetProperty("accessToken").GetString()!;
        Assert.NotNull(token);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var auth = new AuthResponse { Token = token, Email = email, UserId = "", UserName = username };
        return (client, auth);
    }

    [Fact]
    public async Task Authentication_RequiredForFiles()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/files");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Authorization_CannotAccessOthersFiles()
    {
        var (clientA, _) = await RegisterAndLogin("UserA", "a@example.com", "Pass123!");
        var initRes = await clientA.PostAsJsonAsync("/files/init", new InitUploadDto
        {
            EncryptedFileName = "A_file",
            EncryptedManifestHeader = Convert.ToBase64String(new byte[16]),
            WrappedFileKey = "keyA"
        });
        var fileInfo = await initRes.Content.ReadFromJsonAsync<JsonElement>();
        Guid fileId = fileInfo.GetProperty("fileId").GetGuid();

        var (clientB, _) = await RegisterAndLogin("UserB", "b@example.com", "Pass123!");
        var getRes = await clientB.GetAsync($"/files/{fileId}");
        Assert.Equal(HttpStatusCode.NotFound, getRes.StatusCode);
    }

    [Fact]
    public async Task EncryptionAndMetadata_Preserved()
    {
        var (client, _) = await RegisterAndLogin("CryptoUser", "crypto@example.com", "Pass123!");

        string encryptedMetadata = "secret_metadata_blob";
        string recoveryKey = "recovery_key_blob";

        var initRes = await client.PostAsJsonAsync("/files/init", new InitUploadDto
        {
            EncryptedFileName = "encrypted_name",
            EncryptedMetadata = encryptedMetadata,
            RecoveryWrappedKey = recoveryKey,
            EncryptedManifestHeader = Convert.ToBase64String(new byte[16]),
            WrappedFileKey = "wrapped_key"
        });

        var fileInfo = await initRes.Content.ReadFromJsonAsync<JsonElement>();
        Guid fileId = fileInfo.GetProperty("fileId").GetGuid();

        var getRes = await client.GetAsync($"/files/{fileId}");
        var metadata = await getRes.Content.ReadFromJsonAsync<FileMetadataDto>();

        Assert.Equal("encrypted_name", metadata!.FileName);
        Assert.Equal(encryptedMetadata, metadata.EncryptedMetadata);
        Assert.Equal(recoveryKey, metadata.RecoveryWrappedKey);
    }

    [Fact]
    public async Task MfaRecovery_Works()
    {
        var email = "mfa@example.com";
        var pass = "Pass123!";
        var (client, _) = await RegisterAndLogin("MfaUser", email, pass);

        var setupRes = await client.PostAsync("/auth/mfa/setup", null);
        var setupData = await setupRes.Content.ReadFromJsonAsync<JsonElement>();
        string secret = setupData.GetProperty("base32Secret").GetString()!;
        var recoveryCodes = JsonSerializer.Deserialize<List<string>>(setupData.GetProperty("recoveryCodes").GetRawText())!;
        Assert.Equal(10, recoveryCodes.Count);

        var totp = new OtpNet.Totp(OtpNet.Base32Encoding.ToBytes(secret));
        var code = totp.ComputeTotp();
        var verifyRes = await client.PostAsJsonAsync("/auth/mfa/verify", new { code = code });
        Assert.Equal(HttpStatusCode.OK, verifyRes.StatusCode);

        var loginRes1 = await client.PostAsJsonAsync("/auth/login", new LoginRequest { Email = email, Password = pass });
        var loginData1 = await loginRes1.Content.ReadFromJsonAsync<JsonElement>();
        bool mfaReq = loginData1.GetProperty("mfaRequired").GetBoolean();
        string mfaToken = loginData1.GetProperty("mfaToken").GetString()!;
        Assert.True(mfaReq);

        var recoveryRes = await client.PostAsJsonAsync("/auth/login/recovery", new
        {
            mfaToken = mfaToken,
            recoveryCode = recoveryCodes[0]
        });
        Assert.Equal(HttpStatusCode.OK, recoveryRes.StatusCode);
        var finalData = await recoveryRes.Content.ReadFromJsonAsync<JsonElement>();
        string finalToken = finalData.GetProperty("accessToken").GetString()!;
        Assert.NotNull(finalToken);
    }

    [Fact]
    public async Task RateLimiting_Auth_Triggers()
    {
        var client = _factory.CreateClient();
        var email = "rate@example.com";

        for (int i = 0; i < 11; i++)
        {
            await client.PostAsJsonAsync("/auth/login", new LoginRequest { Email = email, Password = "wrong" });
        }

        var blockedRes = await client.PostAsJsonAsync("/auth/login", new LoginRequest { Email = email, Password = "wrong" });
        Assert.Equal((HttpStatusCode)429, blockedRes.StatusCode);
    }

    [Fact]
    public async Task SecurityHeaders_Present()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/auth/register");

        Assert.True(response.Headers.Contains("X-Frame-Options"));
        Assert.True(response.Headers.Contains("X-Content-Type-Options"));
        Assert.True(response.Headers.Contains("Content-Security-Policy"));
    }

    [Fact]
    public async Task Auditing_LogsLogin()
    {
        var email = "audit@example.com";
        var (client, auth) = await RegisterAndLogin("AuditUser", email, "Pass123!");

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var user = await db.Users.FirstAsync(u => u.Email == email);

        var logs = await db.AuditLogs.Where(l => l.UserId == user.Id).ToListAsync();
        Assert.Contains(logs, l => l.Action == "User Registered");
        Assert.Contains(logs, l => l.Action == "User Logged In");
    }

    [Fact]
    public async Task FileLifecycle_Full_Works()
    {
        var (client, _) = await RegisterAndLogin("LifecycleUser", "life@example.com", "Pass123!");

        // 1. Direct Upload
        var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(System.Text.Encoding.UTF8.GetBytes("chunk1chunk2"));
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "file", "test.bin");
        content.Add(new StringContent("meta"), "encryptedMetadata");
        content.Add(new StringContent("key"), "wrappedFileKey");

        var uploadRes = await client.PostAsync("/files/upload", content);
        Assert.Equal(HttpStatusCode.OK, uploadRes.StatusCode);
        var uploadData = await uploadRes.Content.ReadFromJsonAsync<JsonElement>();
        Guid fileId = uploadData.GetProperty("fileId").GetGuid();

        // 2. List Files
        var listRes = await client.GetAsync("/files");
        var list = await listRes.Content.ReadFromJsonAsync<List<FileMetadataDto>>();
        Assert.Contains(list!, f => f.Id == fileId);

        // 3. Download
        var downRes = await client.GetAsync($"/files/{fileId}/download");
        Assert.Equal(HttpStatusCode.OK, downRes.StatusCode);
        var downBytes = await downRes.Content.ReadAsByteArrayAsync();
        Assert.Equal("chunk1chunk2", System.Text.Encoding.UTF8.GetString(downBytes));

        // 4. Delete
        var delRes = await client.DeleteAsync($"/files/{fileId}");
        Assert.Equal(HttpStatusCode.OK, delRes.StatusCode);

        // 5. Verify Deleted
        var getRes = await client.GetAsync($"/files/{fileId}");
        Assert.Equal(HttpStatusCode.NotFound, getRes.StatusCode);
    }

    [Fact]
    public async Task KeyManagement_Works()
    {
        var (client, _) = await RegisterAndLogin("KeyUser", "keyman@example.com", "Pass123!");

        // 1. Register Key
        var regKeyRes = await client.PostAsJsonAsync("/keys/register", new RegisterUserKeyDto
        {
            Algorithm = "RSA",
            PublicKey = "pubkey",
            EncryptedPrivateKey = "privkey"
        });
        Assert.Equal(HttpStatusCode.OK, regKeyRes.StatusCode);

        // 2. Get My Key
        var meRes = await client.GetAsync("/keys/me");
        var myKey = await meRes.Content.ReadFromJsonAsync<UserKeyPair>();
        Assert.Equal("pubkey", myKey!.PublicKey);

        // 3. Get Public Key (Anonymous)
        var anonClient = _factory.CreateClient();
        var pubRes = await anonClient.GetAsync($"/keys/public/{myKey.UserId}");
        Assert.Equal(HttpStatusCode.OK, pubRes.StatusCode);
        var pubKey = await pubRes.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("pubkey", pubKey.GetProperty("publicKey").GetString());
    }

    [Fact]
    public async Task RefreshToken_Works()
    {
        var email = "refresh@example.com";
        var client = _factory.CreateClient();
        await client.PostAsJsonAsync("/auth/register", new RegisterRequest { UserName = "Refresher", Email = email, Password = "Pass123!" });
        var loginRes = await client.PostAsJsonAsync("/auth/login", new LoginRequest { Email = email, Password = "Pass123!" });
        var loginData = await loginRes.Content.ReadFromJsonAsync<JsonElement>();
        string refreshToken = loginData.GetProperty("refreshToken").GetString()!;

        var refreshRes = await client.PostAsJsonAsync("/auth/refresh", new RefreshRequest { RefreshToken = refreshToken });
        Assert.Equal(HttpStatusCode.OK, refreshRes.StatusCode);
        var refreshData = await refreshRes.Content.ReadFromJsonAsync<JsonElement>();
        Assert.NotNull(refreshData.GetProperty("accessToken").GetString());
    }
}
