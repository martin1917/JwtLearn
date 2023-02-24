using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using JwtApi.Dto;
using JwtApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JwtApi.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<AppUser> userManager;
    private readonly IConfiguration config;

    public AuthController(
        UserManager<AppUser> userManager,
        IConfiguration config)
    {
        this.userManager = userManager;
        this.config = config;
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
    {
        var userExist = await userManager.FindByNameAsync(registerDto.Username);
        if (userExist is not null)
        {
            return StatusCode(StatusCodes.Status400BadRequest, new { message = "User already exists!" });
        }

        var user = new AppUser
        {
            Email = registerDto.Email,
            UserName = registerDto.Username,
            SecurityStamp = Guid.NewGuid().ToString()
        };
        var res = await userManager.CreateAsync(user, registerDto.Password);

        if (!res.Succeeded)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new 
            { 
                message = "User creation failed! Please check user details and try again." 
            });
        }

        return StatusCode(StatusCodes.Status200OK, new { message = "User created successfully!" });
    }

    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
    {
        var user = await userManager.FindByNameAsync(loginDto.Username);
        if (user is not null && await userManager.CheckPasswordAsync(user, loginDto.Password))
        {
            var userRoles = await userManager.GetRolesAsync(user);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var jwt = Helper.GenerateJwt(claims, config);
            var refreshToken = Helper.GenerateRefreshToken();
            _ = int.TryParse(config["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(refreshTokenValidityInDays);

            await userManager.UpdateAsync(user);

            return Ok(new TokenDto
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(jwt),
                RefreshToken = refreshToken
            });
        }

        return Unauthorized();
    }

    [HttpPost]
    [Route("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenDto tokenDto)
    {
        var principal = Helper.GetPrincipalFromExpiredToken(tokenDto.AccessToken, config);
        if (principal is null)
        {
            return BadRequest("Invalid access token or refresh token");
        }

        var user = await userManager.FindByNameAsync(principal!.Identity!.Name);
        if (user is null || user.RefreshToken != tokenDto.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            return BadRequest("Invalid access token or refresh token");
        }

        var newJwt = Helper.GenerateJwt(principal.Claims.ToList(), config);
        var newRefresh = Helper.GenerateRefreshToken();
        user.RefreshToken = newRefresh;
        await userManager.UpdateAsync(user);

        return Ok(new TokenDto
        {
            AccessToken = new JwtSecurityTokenHandler().WriteToken(newJwt),
            RefreshToken = newRefresh
        });
    }
}