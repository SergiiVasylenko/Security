using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace Security.Tests;

[TestFixture]
public class TestXssAndEmailCanonicalization
{
    private WebApplicationFactory<Program> _factory = null!;

    [SetUp]
    public void Setup() => _factory = new WebApplicationFactory<Program>();

    [TearDown]
    public void Teardown() => _factory?.Dispose();

    [Test]
    public async Task Submit_Rejects_EmailWithDisplayNameCanonicalization()
    {
        var client = _factory.CreateClient();
        // "Eve <eve@example.com>" will be canonicalized by MailAddress; server should reject due to change
        var resp = await client.PostAsJsonAsync("/submit", new { username = "eve_user", email = "Eve <eve@example.com>" });
        Assert.That((int)resp.StatusCode, Is.EqualTo(400));
        var text = await resp.Content.ReadAsStringAsync();
        Assert.That(text, Does.Contain("Email contains invalid characters").Or.Contains("Invalid email"));
    }

    [Test]
    public async Task Submit_Rejects_JavascriptSchemeInEmail()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/submit", new { username = "js_user", email = "javascript:alert(1)" });
        Assert.That((int)resp.StatusCode, Is.EqualTo(400));
    }

    [Test]
    public async Task Search_Rejects_ScriptLikePayload()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/users/search?term=" + System.Uri.EscapeDataString("<svg onload=alert(1)>"));
        Assert.That((int)resp.StatusCode, Is.EqualTo(400));
    }

    [Test]
    public async Task GetByUsername_Rejects_Xp_Prefix()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/users/by-username/" + System.Uri.EscapeDataString("xp_cmdshell"));
        Assert.That((int)resp.StatusCode, Is.EqualTo(400));
    }
}
