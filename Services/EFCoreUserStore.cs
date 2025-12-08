using FileFox_Backend.Data;
using FileFox_Backend.Models;
using Microsoft.EntityFrameworkCore;
using BCrypt.Net;

namespace FileFox_Backend.Services;

public class EFCoreUserStore : IUserStore
{
    private readonly ApplicationDbContext _db;

    public EFCoreUserStore(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task<(bool Created, User? User, string? Error)> RegisterAsync(
        string userName, string password, CancellationToken ct = default)
    {
        if (await _db.Users.AnyAsync(u => u.UserName == userName, ct))
            return (false, null, "User already exists");

        var hash = BCrypt.Net.BCrypt.HashPassword(password); // bcrypt hash

        var user = new User
        {
            Id = Guid.NewGuid(),
            UserName = userName,
            PasswordHash = hash
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync(ct);

        return (true, user, null);
    }

    public async Task<User?> ValidateCredentialsAsync(
        string userName, string password, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.UserName == userName, ct);
        if (user == null) return null;

        return BCrypt.Net.BCrypt.Verify(password, user.PasswordHash) ? user : null;
    }

    public bool TryGetById(Guid id, out User user)
    {
        user = _db.Users.FirstOrDefault(u => u.Id == id)!;
        return user is not null;
    }
}
