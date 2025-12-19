using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Security.Services;

public static class PasswordHasher
{
    // Argon2id parameters — tune for your environment/test budget
    public const int SaltSize = 16; // bytes
    public const int OutputSize = 32; // bytes
    public const int DegreeOfParallelism = 2; // CPU threads
    public const int Iterations = 3; // passes
    public const int MemorySizeKb = 64 * 1024; // 64 MB

    public static (string Hash, string Salt) HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = DegreeOfParallelism,
            Iterations = Iterations,
            MemorySize = MemorySizeKb
        };
        var hash = argon.GetBytes(OutputSize);
        return (Convert.ToBase64String(hash), Convert.ToBase64String(salt));
    }

    public static bool Verify(string password, string hashBase64, string saltBase64)
    {
        var salt = Convert.FromBase64String(saltBase64);
        var expected = Convert.FromBase64String(hashBase64);
        var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = DegreeOfParallelism,
            Iterations = Iterations,
            MemorySize = MemorySizeKb
        };
        var computed = argon.GetBytes(expected.Length);
        return CryptographicOperations.FixedTimeEquals(computed, expected);
    }
}
