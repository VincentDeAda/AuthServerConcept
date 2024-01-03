using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using System.Buffers.Text;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
	.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);
var app = builder.Build();

string clientUrl = "https://localhost:5001/";
string serverUrl = "https://localhost:6001/";
app.UseAuthentication();
app.UseHttpsRedirection();

app.MapGet("/callback", async (string code, HttpContext ctx) =>
{

	var decodedCode = Convert.FromBase64String(code);
	var stringCode = Encoding.ASCII.GetString(decodedCode);
	var callback = JsonSerializer.Deserialize<CallbackObj>(stringCode);
	if (callback is null)
		return Results.BadRequest("Invalid Code");

	if (DateTime.Now > callback.ExpireationDate)
		return Results.BadRequest("Expired Token");
	var claims = new List<Claim>();
	foreach (var claim in callback.Claims)
		claims.Add(new Claim(claim.Key, claim.Value));
	var claimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
	var claimsPrincipal = new ClaimsPrincipal(claimIdentity);

	await ctx.SignInAsync(claimsPrincipal);
	return Results.Redirect(clientUrl);
});
app.MapGet("/", async (HttpContext ctx) =>
{
	return Results.Ok(ctx.User.Claims.Select(x => new KeyValue(x.Type, x.Value)));


});

app.MapGet("/login", (HttpContext ctx) =>
{

	return Results.Redirect($"{serverUrl}login?callerUrl={HttpUtility.UrlEncode(clientUrl)}");

});
app.Run();


public record KeyValue(string Key, string Value);
public record CallbackObj(DateTime ExpireationDate, KeyValue[] Claims);