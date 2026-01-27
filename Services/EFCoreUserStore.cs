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
        string userName, string email, string password, CancellationToken ct = default)
    {
        if (await _db.Users.AnyAsync(u => u.Email == email, ct))
            return (false, null, "User already exists");

        var hash = BCrypt.Net.BCrypt.HashPassword(password); // bcrypt hash

        var user = new User
        {
            Id = Guid.NewGuid(),
            UserName = userName,
            Email = email,
            PasswordHash = hash
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync(ct);

        return (true, user, null);
    }

    public async Task<User?> ValidateCredentialsAsync(
        string email, string password, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);
        if (user == null) return null;

        return BCrypt.Net.BCrypt.Verify(password, user.PasswordHash) ? user : null;
    }

    public async Task UpdateAsync(User user)
    {
        _db.Users.Update(user);
        await _db.SaveChangesAsync();
    }

    public async Task<(bool Found, User? User)> TryGetByIdAsync(Guid id)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == id);
        return (user != null, user);
    }
}
