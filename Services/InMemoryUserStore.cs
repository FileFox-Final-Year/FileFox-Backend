// This is our simple in-memory list of users.
// It safely remembers usernames and salted password hashes.
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using FileFox_Backend.Models;

namespace FileFox_Backend.Services;

public class InMemoryUserStore : IUserStore
{
    private readonly ConcurrentDictionary<string, User> _byName = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<Guid, User> _byId = new();

    // Make a new user if the name isn't taken
    public Task<(bool Created, User? User, string? Error)> RegisterAsync(string userName, string password, CancellationToken ct = default)
    {
        userName = userName.Trim();
        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrEmpty(password))
            return Task.FromResult((false, (User?)null, "Username and password are required"));

        if (_byName.ContainsKey(userName))
            return Task.FromResult((false, (User?)null, "Username already exists"));

        var (hash, salt) = HashPassword(password);
        var user = new User
        {
            Id = Guid.NewGuid(),
            UserName = userName,
            PasswordHash = hash,
            PasswordSalt = salt,
            CreatedAt = DateTimeOffset.UtcNow
        };

        if (!_byName.TryAdd(userName, user))
            return Task.FromResult((false, (User?)null, "Username already exists"));
        _byId[user.Id] = user;
        return Task.FromResult((true, user, (string?)null));
    }

    // Check if the username and password are correct
    public Task<User?> ValidateCredentialsAsync(string userName, string password, CancellationToken ct = default)
    {
        if (_byName.TryGetValue(userName, out var user) && VerifyPassword(password, user.PasswordHash, user.PasswordSalt))
            return Task.FromResult<User?>(user);
        return Task.FromResult<User?>(null);
    }

    public bool TryGetById(Guid id, out User user) => _byId.TryGetValue(id, out user!);

    // Turn a password into a salted hash so we never store the plain text
    private static (byte[] Hash, byte[] Salt) HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        using var derive = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
        return (derive.GetBytes(32), salt);
    }

    // Check that a password makes the same hash with the same salt
    private static bool VerifyPassword(string password, byte[] hash, byte[] salt)
    {
        using var derive = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
        var attempt = derive.GetBytes(32);
        return CryptographicOperations.FixedTimeEquals(attempt, hash);
    }
}