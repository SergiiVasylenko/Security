using System.Net.Http.Json;
using System;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Security.Tests;

[TestFixture]
public class TestParameterizedQueries
{
    private WebApplicationFactory<Program> _factory = null!;

    [SetUp]
    public void Setup() => _factory = new WebApplicationFactory<Program>();

    [TearDown]
    public void Teardown() => _factory?.Dispose();

    [Test]
    public async Task GetByUsername_BlocksSQLi()
    {
        var client = _factory.CreateClient();

        // Seed a valid user
        var ok = await client.PostAsJsonAsync("/submit", new { username = "alice", email = "alice@example.com" });
        ok.EnsureSuccessStatusCode();

        // Attempt SQL injection-like username
        var resp = await client.GetAsync("/users/by-username/" + Uri.EscapeDataString("alice' OR 1=1 --"));
        Assert.That((int)resp.StatusCode, Is.EqualTo(400));

        // Valid lookup should work
        var good = await client.GetAsync("/users/by-username/alice");
        good.EnsureSuccessStatusCode();
        var body = await good.Content.ReadAsStringAsync();
        Assert.That(body, Does.Contain("\"username\":\"alice\""));
    }

    [Test]
    public async Task Search_UsesEscapedLikeAndParameters()
    {
        var client = _factory.CreateClient();

        // Seed a few users
        foreach (var (u, e) in new[] { ("safe_one", "one@example.com"), ("safe_two", "two@example.com"), ("other", "o@example.com") })
        {
            var r = await client.PostAsJsonAsync("/submit", new { username = u, email = e });
            r.EnsureSuccessStatusCode();
        }

        // Search by prefix
        var res = await client.GetAsync("/users/search?term=" + Uri.EscapeDataString("safe"));
        res.EnsureSuccessStatusCode();
        var json = await res.Content.ReadAsStringAsync();
        Assert.That(json, Does.Contain("safe_one"));
        Assert.That(json, Does.Contain("safe_two"));
        Assert.That(json, Does.Not.Contain("other\""));

        // Ensure wildcard chars are escaped and do not match everything
        var wildcard = await client.GetAsync("/users/search?term=" + Uri.EscapeDataString("%_"));
        wildcard.EnsureSuccessStatusCode();
        var wjson = await wildcard.Content.ReadAsStringAsync();
        // Should not return all users just because of wildcards
        Assert.That(wjson, Does.Not.Contain("\"Username\":\"alice\""));

        // Attempt an injection-like search term
        var inj = await client.GetAsync("/users/search?term=" + Uri.EscapeDataString("safe%' OR 1=1 --"));
        // Rejected for dangerous pattern
        Assert.That((int)inj.StatusCode, Is.EqualTo(400));
    }
}
