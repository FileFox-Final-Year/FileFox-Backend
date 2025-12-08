using FileFox_Backend.Models;
public interface IUserStore
{
    Task<(bool Created, User? User, string? Error)> RegisterAsync(string userName, string password, CancellationToken ct = default);
    Task<User?> ValidateCredentialsAsync(string userName, string password, CancellationToken ct = default);
    bool TryGetById(Guid id, out User user);
}
