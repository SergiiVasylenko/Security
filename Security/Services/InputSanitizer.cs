using System.Net.Mail;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

namespace Security.Services;

public static class InputSanitizer
{
    private static readonly Regex UsernameInvalidChars = new("[^A-Za-z0-9_.-]", RegexOptions.Compiled);
    private static readonly Regex DangerousPattern = new(
        // Detect common XSS and SQLi markers in a conservative way
        "(" +
        "<\\s*script\\b" + // <script>
        "|on[\\w-]+\\s*=" + // inline event handlers like onerror=
        "|javascript:" +
        "|vbscript:" +
        "|data\\s*:\\s*text/(html|javascript)" +
        "|<\\s*(iframe|svg|math)\\b" +
        "|['\"`];?\\s*--" + // comment-based SQLi tail
        "|/\\*|\\*/" +     // SQL/JS comment blocks
        "|\\bor\\b\\s*['\" ]?1\\s*=\\s*['\" ]?1" + // OR 1=1 (with/without quotes)
        "|\\bxp_" +          // xp_cmdshell and similar
        ")",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static bool IsDangerous(string input)
        => !string.IsNullOrEmpty(input) && DangerousPattern.IsMatch(input);

    public static string SanitizeUsername(string input, out bool changed)
    {
        var normalized = (input ?? string.Empty).Trim();
        var cleaned = UsernameInvalidChars.Replace(normalized, string.Empty);
        cleaned = cleaned.Length > 100 ? cleaned.Substring(0, 100) : cleaned;
        changed = !string.Equals(cleaned, normalized, StringComparison.Ordinal);
        return cleaned;
    }

    public static string SanitizeEmail(string input, out bool changed)
    {
        var normalized = (input ?? string.Empty).Trim();
        // remove control chars only (keep logic aligned with model validation)
        var cleaned = Regex.Replace(normalized, "[\\p{C}]", string.Empty);
        cleaned = cleaned.Length > 100 ? cleaned.Substring(0, 100) : cleaned;
        // Validate email shape using MailAddress and detect ambiguous canonicalization
        var addr = new MailAddress(cleaned);
        var canonical = addr.Address;
        // Mark as changed if MailAddress had to strip display names/comments or if casing differs meaningfully
        changed = !string.Equals(canonical, cleaned, StringComparison.Ordinal);
        return canonical.ToLowerInvariant();
    }

    public static string HtmlEncode(string value) => HtmlEncoder.Default.Encode(value ?? string.Empty);
}
