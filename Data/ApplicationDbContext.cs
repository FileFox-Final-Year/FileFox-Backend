using FileFox_Backend.Models;
using Microsoft.EntityFrameworkCore;

namespace FileFox_Backend.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<FileRecord> Files { get; set; }
    }
}
