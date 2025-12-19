using Microsoft.Data.Sqlite;
using System.Text.Encodings.Web;

namespace Security.Data;

public class UsersRepository
{
    private readonly string _connectionString;

    public UsersRepository(string connectionString)
    {
        _connectionString = connectionString;
        EnsureSchema();
    }

    private void EnsureSchema()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"CREATE TABLE IF NOT EXISTS Users (
            UserID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL,
            Email TEXT NOT NULL
        );";
        cmd.ExecuteNonQuery();

        // Add missing columns for authentication if needed
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var info = conn.CreateCommand())
        {
            info.CommandText = "PRAGMA table_info(Users);";
            using var r = info.ExecuteReader();
            while (r.Read()) existing.Add(r.GetString(1));
        }
        void AddColumn(string name, string ddl)
        {
            if (!existing.Contains(name))
            {
                using var alter = conn.CreateCommand();
                alter.CommandText = $"ALTER TABLE Users ADD COLUMN {name} {ddl};";
                alter.ExecuteNonQuery();
            }
        }
        AddColumn("PasswordHash", "TEXT");
        AddColumn("PasswordSalt", "TEXT");
        AddColumn("Role", "TEXT");
        using (var setDefault = conn.CreateCommand())
        {
            setDefault.CommandText = "UPDATE Users SET Role = COALESCE(Role, 'User') WHERE Role IS NULL;";
            setDefault.ExecuteNonQuery();
        }
    }

    public long InsertUser(string username, string email)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO Users (Username, Email) VALUES ($username, $email);";
        cmd.Parameters.AddWithValue("$username", username);
        cmd.Parameters.AddWithValue("$email", email);
        cmd.ExecuteNonQuery();

        // last_insert_rowid() is safe per-connection in SQLite
        using var idCmd = conn.CreateCommand();
        idCmd.CommandText = "SELECT last_insert_rowid();";
        return (long)(idCmd.ExecuteScalar() ?? 0L);
    }

    public (long UserID, string Username, string Email)? GetUser(long id)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT UserID, Username, Email FROM Users WHERE UserID = $id";
        cmd.Parameters.AddWithValue("$id", id);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        return (reader.GetInt64(0), reader.GetString(1), reader.GetString(2));
    }

    public (long UserID, string Username, string Email)? GetUserByUsername(string username)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT UserID, Username, Email FROM Users WHERE Username = $username";
        cmd.Parameters.AddWithValue("$username", username);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        return (reader.GetInt64(0), reader.GetString(1), reader.GetString(2));
    }

    public IReadOnlyList<(long UserID, string Username, string Email)> SearchUsers(string term)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        // Escape SQLite LIKE wildcards and backslash
        var escaped = term
            .Replace("\\", "\\\\")
            .Replace("%", "\\%")
            .Replace("_", "\\_");
        var pattern = "%" + escaped + "%";

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT UserID, Username, Email FROM Users WHERE Username LIKE $pattern ESCAPE '\\' ORDER BY UserID";
        cmd.Parameters.AddWithValue("$pattern", pattern);
        using var reader = cmd.ExecuteReader();
        var list = new List<(long, string, string)>();
        while (reader.Read())
        {
            list.Add((reader.GetInt64(0), reader.GetString(1), reader.GetString(2)));
        }
        return list;
    }

    public long RegisterUser(string username, string email, string passwordHash, string passwordSalt, string role)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        using (var check = conn.CreateCommand())
        {
            check.CommandText = "SELECT 1 FROM Users WHERE Username = $username";
            check.Parameters.AddWithValue("$username", username);
            using var rr = check.ExecuteReader();
            if (rr.Read()) throw new InvalidOperationException("Username already exists.");
        }

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"INSERT INTO Users (Username, Email, PasswordHash, PasswordSalt, Role)
                            VALUES ($username, $email, $hash, $salt, $role);";
        cmd.Parameters.AddWithValue("$username", username);
        cmd.Parameters.AddWithValue("$email", email);
        cmd.Parameters.AddWithValue("$hash", passwordHash);
        cmd.Parameters.AddWithValue("$salt", passwordSalt);
        cmd.Parameters.AddWithValue("$role", role);
        cmd.ExecuteNonQuery();
        using var idCmd = conn.CreateCommand();
        idCmd.CommandText = "SELECT last_insert_rowid();";
        return (long)(idCmd.ExecuteScalar() ?? 0L);
    }

    public (long UserID, string Username, string Email, string? PasswordHash, string? PasswordSalt, string Role)? GetAuthUser(string username)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT UserID, Username, Email, PasswordHash, PasswordSalt, COALESCE(Role,'User') FROM Users WHERE Username = $username";
        cmd.Parameters.AddWithValue("$username", username);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        return (
            reader.GetInt64(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.IsDBNull(3) ? null : reader.GetString(3),
            reader.IsDBNull(4) ? null : reader.GetString(4),
            reader.GetString(5)
        );
    }
}
