using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using JWTAuth.Entities;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;

namespace JWTAuth.Controllers
{
  [Route("[controller]")]
  [ApiController]
  public class AuthController : ControllerBase
  {
    private readonly string key;
    private readonly IConfiguration configuration;
    private readonly List<User> users = new List<User>();
    public AuthController(IConfiguration configuration)
    {
      this.configuration = configuration;
      this.key = configuration["key"];
      User user = new User();
      user.Id = 234;
      user.Name = "name";
      user.Password = "pass";
      users.Add(user);
    }
    [HttpPost("signin")]
    public IActionResult Signin([FromBody] User user)
    {
      users.Add(user);
      return Ok(users);
    }
    [HttpPost("login")]
    public IActionResult Login([FromBody] User user)
    {
      if(!users.Any(u => u.Name == user.Name && u.Password == user.Password))
      {
        return Unauthorized();
      }
      var tokenHandler = new JwtSecurityTokenHandler();
      var tokenKey = Encoding.ASCII.GetBytes(key);
      var tokenDescriptor = new SecurityTokenDescriptor
      {
        Subject = new ClaimsIdentity(new Claim[]
        {
          new Claim(ClaimTypes.Name, user.Name)
        }),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(
          new SymmetricSecurityKey(tokenKey),
          SecurityAlgorithms.HmacSha256Signature
        )
      };
      var token = tokenHandler.CreateToken(tokenDescriptor);
      return Ok(tokenHandler.WriteToken(token));
    }
  }
}
