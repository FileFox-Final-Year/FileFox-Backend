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
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<FileKey> FileKeys { get; set; } = null!;
        public DbSet<AuditLog> AuditLogs { get; set; } = null!;
        public DbSet<UserKeyPair> UserKeyPairs { get; set; } = null!;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            
            modelBuilder.Entity<FileKey>()
                .HasOne(k => k.FileRecord)
                .WithMany(f => f.Keys)
                .HasForeignKey(k => k.FileRecordId);
        }
    }
}
