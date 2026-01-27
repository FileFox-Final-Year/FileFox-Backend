using FileFox_Backend.Models;

namespace FileFox_Backend.Services;

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
}
