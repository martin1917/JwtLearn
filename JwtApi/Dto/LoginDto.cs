using System.ComponentModel.DataAnnotations;

namespace JwtApi.Dto;

public class LoginDto
{
    [Required(ErrorMessage = "User Name is required") ]
    public string Username { get; set; } = null!;

    [Required(ErrorMessage = "Password is required") ]
    public string Password { get; set; } = null!;
}