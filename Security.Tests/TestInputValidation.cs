using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace Security.Tests;

[TestFixture]
public class TestInputValidation
{
    private WebApplicationFactory<Program> _factory = null!;

    [SetUp]
    public void Setup()
    {
        _factory = new WebApplicationFactory<Program>();
    }

    [TearDown]
    public void Teardown() => _factory?.Dispose();

    [Test]
    public async Task TestForSQLInjection()
    {
        var client = _factory.CreateClient();
        var malicious = new { username = "admin'; DROP TABLE Users; --", email = "attacker@example.com" };

        var resp = await client.PostAsJsonAsync("/submit", malicious);

        // Should be rejected by validation due to invalid username characters
        Assert.That((int)resp.StatusCode, Is.EqualTo(400));

        // Now ensure table still exists by inserting a valid user
        var good = new { username = "safe_user", email = "safe@example.com" };
        var okResp = await client.PostAsJsonAsync("/submit", good);
        okResp.EnsureSuccessStatusCode();
        var created = await okResp.Content.ReadFromJsonAsync<CreatedUser>();
        Assert.That(created, Is.Not.Null);
        Assert.That(created!.userId, Is.GreaterThan(0));
    }

    [Test]
    public async Task TestForXSS()
    {
        var client = _factory.CreateClient();
        var payload = new { username = "<script>alert('x')</script>", email = "xss@example.com" };

        // Username with angle brackets should fail regex validation
        var resp = await client.PostAsJsonAsync("/submit", payload);
        Assert.That((int)resp.StatusCode, Is.EqualTo(400));

        // Insert a value that includes harmless HTML-like text after encoding (allowed characters only)
        var safe = new { username = "user_safe", email = "test@example.com" };
        var ok = await client.PostAsJsonAsync("/submit", safe);
        ok.EnsureSuccessStatusCode();
        var doc = await ok.Content.ReadFromJsonAsync<CreatedUser>();
        Assert.That(doc, Is.Not.Null);

        // Read back and ensure JSON contains no unescaped HTML from server (System.Text.Json escapes by default)
        var get = await client.GetAsync($"/users/{doc!.userId}");
        get.EnsureSuccessStatusCode();
        var json = await get.Content.ReadAsStringAsync();
        // The response should not contain raw script tags
        Assert.That(json, Does.Not.Contain("<script>"));
    }

    private record CreatedUser(long userId);
}
