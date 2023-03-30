using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Claims;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Net.Http.Headers;

namespace SessionFixationRepro;

public class Repro
{
    [Theory, InlineData(true), InlineData(false)]
    public async Task SessionId_ShouldNotBeShared_BetweenMultipleAuthenticationCookies(bool useSessionStore)
    {
        var factory = new CustomFactory(useSessionStore);
        var userClient = factory.CreateClient();

        // Start a user session and extract the cookies from the response
        var response = await userClient.GetAsync("/signin");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Ensure the the user 
        var userClientRole = await (await userClient.GetAsync("/whoami")).Content.ReadAsStringAsync();
        Assert.Equal("User", userClientRole);

        // Make a copy of the authentication (and other) cookies and include them in adminClient
        var adminClient = factory.CreateClient();
        var container = new CookieContainer();
        Assert.True(response.Headers.TryGetValues(HeaderNames.SetCookie, out var setCookieHeaders));
        foreach (var cookie in setCookieHeaders)
        {
            container.SetCookies(userClient.BaseAddress!, cookie);
        }

        // Request step-up authentication, including the original cookies only for this request
        // The cookies will not be added to adminClient's internal cookie container
        var requestMessage = new HttpRequestMessage
        {
            Method = HttpMethod.Get,
            RequestUri = new Uri("/stepup", UriKind.Relative),
        };
        requestMessage.Headers.Add(HeaderNames.Cookie, container.GetCookieHeader(userClient.BaseAddress!));

        response = await adminClient.SendAsync(requestMessage);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Ensure the adminClient's role has been elevated
        var adminClientRole = await (await adminClient.GetAsync("/whoami")).Content.ReadAsStringAsync();
        Assert.Equal("Admin", adminClientRole);

        // Validate the userClient's role has not been elevated
        userClientRole = await (await userClient.GetAsync("/whoami")).Content.ReadAsStringAsync();
        Assert.Equal("User", userClientRole);
    }
}

public class CustomFactory : WebApplicationFactory<Repro>
{
    private readonly bool _useSessionStore;

    public CustomFactory(bool useSessionStore)
    {
        _useSessionStore = useSessionStore;
    }

    protected override IHostBuilder CreateHostBuilder()
    {
        return Host.CreateDefaultBuilder();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseStartup<Startup>();
        builder.ConfigureServices(services =>
        {
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.SessionStore = _useSessionStore ? new InMemoryTicketStore() : null;
                });
        });
    }
}

public class InMemoryTicketStore : ITicketStore
{
    private readonly ConcurrentDictionary<string, byte[]> _tickets = new();

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var id = Guid.NewGuid().ToString();
        _tickets[id] = TicketSerializer.Default.Serialize(ticket);
        return Task.FromResult(id);
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        _tickets[key] = TicketSerializer.Default.Serialize(ticket);
        return Task.CompletedTask;
    }

    public Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        AuthenticationTicket? ticket = null;

        if (_tickets.TryGetValue(key, out var value))
        {
            ticket = TicketSerializer.Default.Deserialize(value);
        }

        return Task.FromResult(ticket);
    }

    public Task RemoveAsync(string key)
    {
        _tickets.TryRemove(key, out _);
        return Task.CompletedTask;
    }
}

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddRouting();
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseAuthentication();
        app.UseRouting();
        app.UseEndpoints(builder =>
        {
            builder.MapGet("/whoami", async context =>
            {
                var user = context.User;
                var role = user.FindAll(ClaimTypes.Role).Single();

                await context.Response.WriteAsync(role.Value);
            });

            builder.MapGet("/signin", async context =>
            {
                await context.SignInAsync(BuildPrincipal("User"));
            }).WithMetadata(new AllowAnonymousAttribute());

            builder.MapGet("/stepup", async context =>
            {
                await context.SignInAsync(BuildPrincipal("Admin"));
            });
        });
    }

    private ClaimsPrincipal BuildPrincipal(string role)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Role, role)
        };

        return new(new ClaimsIdentity(claims, "Testing"));
    }
}
