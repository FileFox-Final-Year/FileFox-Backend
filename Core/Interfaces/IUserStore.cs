using FileFox_Backend.Core.Models;

namespace FileFox_Backend.Core.Interfaces;

public interface IUserStore
{
    Task<(bool Created, User? User, string? Error)> RegisterAsync(
        string userName,
        string email,
        string password,
        CancellationToken ct = default
    );

    Task<User?> ValidateCredentialsAsync(
        string email,
        string password,
        CancellationToken ct = default
    );

    Task UpdateAsync(User user);

    Task<(bool Found, User? User)> TryGetByIdAsync(Guid id);

    Task<User?> GetByEmailAsync(string email, CancellationToken ct = default);

    Task<User?> GetByResetTokenAsync(string token, CancellationToken ct = default);
}
