using System;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace Security.Tests;

[TestFixture]
public class TestAuth
{
    private WebApplicationFactory<Program> _factory = null!;

    [SetUp]
    public void Setup() => _factory = new WebApplicationFactory<Program>();

    [TearDown]
    public void Teardown() => _factory?.Dispose();

    [Test]
    public async Task Admin_Can_Access_AdminOnly()
    {
        var client = _factory.CreateClient();
        var suffix = Guid.NewGuid().ToString("N").Substring(0, 6);
        var adminUser = $"admin_{suffix}";
        // Register admin
        var reg = await client.PostAsJsonAsync("/auth/register", new { username = adminUser, email = $"a{suffix}@ex.com", password = "StrongPass!123", role = "Admin" });
        if (!reg.IsSuccessStatusCode && (int)reg.StatusCode != 409)
        {
            Assert.Fail($"Register admin failed: {(int)reg.StatusCode} {await reg.Content.ReadAsStringAsync()}");
        }

        // Login admin
        var login = await client.PostAsJsonAsync("/auth/login", new { username = adminUser, password = "StrongPass!123" });
        login.EnsureSuccessStatusCode();
        var tokenObj = await login.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.That(tokenObj, Is.Not.Null);
        Assert.That(tokenObj!.token, Is.Not.Null.And.Not.Empty);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenObj.token);
        var resp = await client.GetAsync("/admin/secure");
        resp.EnsureSuccessStatusCode();
        var text = await resp.Content.ReadAsStringAsync();
        Assert.That(text, Does.Contain("Admin access granted"));
    }

    [Test]
    public async Task NonAdmin_Is_Forbidden_On_AdminOnly()
    {
        var client = _factory.CreateClient();
        var suffix = Guid.NewGuid().ToString("N").Substring(0, 6);
        var normalUser = $"user_{suffix}";
        // Register normal user
        var reg = await client.PostAsJsonAsync("/auth/register", new { username = normalUser, email = $"n{suffix}@ex.com", password = "StrongPass!123", role = "User" });
        if (!reg.IsSuccessStatusCode && (int)reg.StatusCode != 409)
        {
            Assert.Fail($"Register user failed: {(int)reg.StatusCode} {await reg.Content.ReadAsStringAsync()}");
        }

        // Login user
        var login = await client.PostAsJsonAsync("/auth/login", new { username = normalUser, password = "StrongPass!123" });
        login.EnsureSuccessStatusCode();
        var tokenObj = await login.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.That(tokenObj, Is.Not.Null);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenObj!.token);
        var resp = await client.GetAsync("/admin/secure");
        Assert.That((int)resp.StatusCode, Is.EqualTo(403));
    }

    [Test]
    public async Task Unauthenticated_Is_Unauthorized_On_AdminOnly()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/admin/secure");
        Assert.That((int)resp.StatusCode, Is.EqualTo(401));
    }

    [Test]
    public async Task Admin_Can_Access_Dashboard_Html()
    {
        var client = _factory.CreateClient();
        var suffix = Guid.NewGuid().ToString("N").Substring(0, 6);
        var adminUser = $"admin_{suffix}";
        var reg = await client.PostAsJsonAsync("/auth/register", new { username = adminUser, email = $"ad{suffix}@ex.com", password = "StrongPass!123", role = "Admin" });
        if (!reg.IsSuccessStatusCode && (int)reg.StatusCode != 409)
        {
            Assert.Fail($"Register admin failed: {(int)reg.StatusCode} {await reg.Content.ReadAsStringAsync()}");
        }
        var login = await client.PostAsJsonAsync("/auth/login", new { username = adminUser, password = "StrongPass!123" });
        login.EnsureSuccessStatusCode();
        var tokenObj = await login.Content.ReadFromJsonAsync<TokenResponse>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenObj!.token);

        var resp = await client.GetAsync("/admin/dashboard");
        resp.EnsureSuccessStatusCode();
        Assert.That(resp.Content.Headers.ContentType!.MediaType, Is.EqualTo("text/html"));
        var html = await resp.Content.ReadAsStringAsync();
        Assert.That(html, Does.Contain("Admin Dashboard"));
    }

    private record TokenResponse(string token);

    [Test]
    public async Task Login_WrongPassword_Returns401()
    {
        var client = _factory.CreateClient();
        var suffix = Guid.NewGuid().ToString("N").Substring(0, 6);
        var user = $"user_{suffix}";
        var reg = await client.PostAsJsonAsync("/auth/register", new { username = user, email = $"t{suffix}@ex.com", password = "CorrectHorseBatteryStaple!1", role = "User" });
        if (!reg.IsSuccessStatusCode && (int)reg.StatusCode != 409)
        {
            Assert.Fail($"Register failed: {(int)reg.StatusCode} {await reg.Content.ReadAsStringAsync()}");
        }
        var login = await client.PostAsJsonAsync("/auth/login", new { username = user, password = "WrongPassword!" });
        Assert.That((int)login.StatusCode, Is.EqualTo(401));
    }

    [Test]
    public async Task Login_UnknownUser_Returns401()
    {
        var client = _factory.CreateClient();
        var login = await client.PostAsJsonAsync("/auth/login", new { username = "does_not_exist_user", password = "whatever" });
        Assert.That((int)login.StatusCode, Is.EqualTo(401));
    }

    [Test]
    public async Task Admin_WithInvalidToken_Returns401()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "not.a.valid.jwt");
        var resp = await client.GetAsync("/admin/secure");
        Assert.That((int)resp.StatusCode, Is.EqualTo(401));
    }
}
