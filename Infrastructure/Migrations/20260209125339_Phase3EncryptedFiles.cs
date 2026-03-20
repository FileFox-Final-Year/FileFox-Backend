using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FileFox_Backend.Migrations
{
    /// <inheritdoc />
    public partial class Phase3EncryptedFiles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Bytes",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "FilePath",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "Length",
                table: "Files");

            migrationBuilder.RenameColumn(
                name: "PrivateKey",
                table: "UserKeyPairs",
                newName: "EncryptedPrivateKey");

            migrationBuilder.RenameColumn(
                name: "FileName",
                table: "Files",
                newName: "ManifestBlobPath");

            migrationBuilder.RenameColumn(
                name: "ContentType",
                table: "Files",
                newName: "EncryptedFileName");

            migrationBuilder.RenameColumn(
                name: "KeyValue",
                table: "FileKeys",
                newName: "WrappedFileKey");

            migrationBuilder.RenameColumn(
                name: "KeyName",
                table: "FileKeys",
                newName: "Algorithm");

            migrationBuilder.AddColumn<int>(
                name: "ChunkSize",
                table: "Files",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "CryptoVersion",
                table: "Files",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<int>(
                name: "KeyVersion",
                table: "FileKeys",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ChunkSize",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "CryptoVersion",
                table: "Files");

            migrationBuilder.DropColumn(
                name: "KeyVersion",
                table: "FileKeys");

            migrationBuilder.RenameColumn(
                name: "EncryptedPrivateKey",
                table: "UserKeyPairs",
                newName: "PrivateKey");

            migrationBuilder.RenameColumn(
                name: "ManifestBlobPath",
                table: "Files",
                newName: "FileName");

            migrationBuilder.RenameColumn(
                name: "EncryptedFileName",
                table: "Files",
                newName: "ContentType");

            migrationBuilder.RenameColumn(
                name: "WrappedFileKey",
                table: "FileKeys",
                newName: "KeyValue");

            migrationBuilder.RenameColumn(
                name: "Algorithm",
                table: "FileKeys",
                newName: "KeyName");

            migrationBuilder.AddColumn<byte[]>(
                name: "Bytes",
                table: "Files",
                type: "varbinary(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "FilePath",
                table: "Files",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "Length",
                table: "Files",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);
        }
    }
}
