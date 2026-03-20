using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FileFox_Backend.Migrations
{
    /// <inheritdoc />
    public partial class FinalizeFileEntities : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Target",
                table: "AuditLogs");

            migrationBuilder.AddColumn<Guid>(
                name: "FileRecordId",
                table: "AuditLogs",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_FileRecordId",
                table: "AuditLogs",
                column: "FileRecordId");

            migrationBuilder.AddForeignKey(
                name: "FK_AuditLogs_Files_FileRecordId",
                table: "AuditLogs",
                column: "FileRecordId",
                principalTable: "Files",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AuditLogs_Files_FileRecordId",
                table: "AuditLogs");

            migrationBuilder.DropIndex(
                name: "IX_AuditLogs_FileRecordId",
                table: "AuditLogs");

            migrationBuilder.DropColumn(
                name: "FileRecordId",
                table: "AuditLogs");

            migrationBuilder.AddColumn<string>(
                name: "Target",
                table: "AuditLogs",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }
    }
}
