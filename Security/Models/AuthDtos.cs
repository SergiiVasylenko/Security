using System.ComponentModel.DataAnnotations;

namespace Security.Models;

public class RegisterDto
{
    [Required, StringLength(100, MinimumLength = 3)]
    [RegularExpression(@"^[A-Za-z0-9_.-]+$")]
    public string Username { get; set; } = string.Empty;

    [Required, EmailAddress, StringLength(100)]
    public string Email { get; set; } = string.Empty;

    [Required, StringLength(200, MinimumLength = 8)]
    public string Password { get; set; } = string.Empty;

    [Required]
    [RegularExpression(@"^(Admin|User)$")] // tight role allow-list
    public string Role { get; set; } = "User";
}

public class LoginDto
{
    [Required]
    public string Username { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}
