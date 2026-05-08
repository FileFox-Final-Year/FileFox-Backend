using Microsoft.AspNetCore.Mvc;
using FileFox_Backend.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace FileFox_Backend.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TestController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _env;

        public TestController(ApplicationDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }

        [HttpGet("test-error")]
        public IActionResult ThrowError()
        {
            // This will simulate a server error
            throw new Exception("This is a test exception for global middleware.");
        }

        [HttpPost("clear-data")]
        public async Task<IActionResult> ClearData()
        {
            // Safety guard: only allow this in Development or when using InMemory database (for tests)
            if (!_env.IsDevelopment() && _context.Database.ProviderName != "Microsoft.EntityFrameworkCore.InMemory")
            {
                return NotFound();
            }

            if (_context.Database.ProviderName == "Microsoft.EntityFrameworkCore.InMemory")
            {
                _context.Blobs.RemoveRange(_context.Blobs);
                _context.AuditLogs.RemoveRange(_context.AuditLogs);
                _context.FileKeys.RemoveRange(_context.FileKeys);
                _context.RefreshTokens.RemoveRange(_context.RefreshTokens);
                _context.UserKeyPairs.RemoveRange(_context.UserKeyPairs);
                _context.Files.RemoveRange(_context.Files);
                _context.Users.RemoveRange(_context.Users);
                await _context.SaveChangesAsync();
            }
            else
            {
                // Clear all tables in an order that respects foreign key constraints
                await _context.Database.ExecuteSqlRawAsync("DELETE FROM Blobs");
                await _context.Database.ExecuteSqlRawAsync("DELETE FROM AuditLogs");
                await _context.Database.ExecuteSqlRawAsync("DELETE FROM FileKeys");
                await _context.Database.ExecuteSqlRawAsync("DELETE FROM RefreshTokens");
                await _context.Database.ExecuteSqlRawAsync("DELETE FROM UserKeyPairs");
                await _context.Database.ExecuteSqlRawAsync("DELETE FROM Files");
                await _context.Database.ExecuteSqlRawAsync("DELETE FROM Users");
            }

            return Ok(new { message = "All data cleared successfully." });
        }
    }
}