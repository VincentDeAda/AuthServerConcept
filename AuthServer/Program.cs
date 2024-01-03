//Server
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
	.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);


var app = builder.Build();
app.UseAuthentication();
app.UseHttpsRedirection();


app.MapGet("/login", (string callerUrl, HttpContext httpContext) =>
{
	httpContext.Response.Headers.ContentType = "text/html";

	httpContext.Response.WriteAsync($"""

		<html>

		<head>KF-Login</head>

		<body>
			<form method="post" action="/login?callerUrl={HttpUtility.UrlEncode(callerUrl)}">
				<input name="username" value="username" />
				<input type="submit" value="submit">
			</form>
		</body>

		</html>

		""");



});


app.MapPost("/login", async ([FromQuery] string callerUrl, [FromForm] string username, HttpContext ctx) =>
{
	var claims = new List<Claim>();
	if (username == "Admin")
		claims.Add(new Claim(ClaimTypes.Role, "admin"));
	else if (username == "User")
		claims.Add(new Claim(ClaimTypes.Role, "user"));
	else
		return Results.BadRequest("No User");


	var claimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
	var claimsPrincipal = new ClaimsPrincipal(claimIdentity);
	await ctx.SignInAsync(claimsPrincipal);

	var usrClaims = claims.Select(x => new KeyValue(x.Type, x.Value)).ToArray();


	var userData = new CallbackObj(DateTime.Now.AddMinutes(5), usrClaims);
	var userDataJson = JsonSerializer.Serialize(userData);
	var userDataBytes = Encoding.ASCII.GetBytes(userDataJson);

	var veryNotSecretToken = Convert.ToBase64String(userDataBytes);

	Console.WriteLine(userDataJson + " " + veryNotSecretToken);

	return Results.Redirect ($"{callerUrl}callback?code={HttpUtility.UrlEncode(veryNotSecretToken)}");


}).DisableAntiforgery();



app.Run();


public record ExternalLoginRequest(string Username, string CallerUrl);
public record KeyValue(string Key, string Value);
public record CallbackObj(DateTime ExpireationDate, KeyValue[] Claims);