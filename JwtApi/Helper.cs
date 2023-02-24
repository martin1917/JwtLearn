using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace JwtApi;

public static class Helper
{
    public static ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token, IConfiguration config)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:Secret"])),
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
        return principal;
    }

    public static JwtSecurityToken GenerateJwt(List<Claim> authClaims, IConfiguration config)
    {
        var authSignKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:Secret"]));
        _ = int.TryParse(config["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);

        return new JwtSecurityToken(
            issuer: config["JWT:Issuer"],
            audience: config["JWT:Audience"],
            expires: DateTime.UtcNow.AddMinutes(tokenValidityInMinutes),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSignKey, SecurityAlgorithms.HmacSha256)
        );
    }

    public static string GenerateRefreshToken()
    {
        var randonNumber = new byte[64];
        using var rnd = RandomNumberGenerator.Create();
        rnd.GetBytes(randonNumber);
        return Convert.ToBase64String(randonNumber);
    }
}