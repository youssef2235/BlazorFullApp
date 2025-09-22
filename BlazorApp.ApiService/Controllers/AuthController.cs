using BlazorApp.BL.Services;
using BlazorApp.Model.Entities;
using BlazorApp.Model.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace BlazorApp.ApiService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IConfiguration configuration, IAuthService authService) : ControllerBase
    {
        [HttpPost("login")]
        public async Task<ActionResult<LoginResponseModel>> Login([FromBody] LoginModel loginModel)
        {
            try
            {
                var user = await authService.GetUserByLogin(loginModel.Username, loginModel.Password);
                var token = GenerateJwtToken(user, isRefreshToken:false);
                var refreshToken = GenerateJwtToken(user, isRefreshToken: true);

                await authService.AddRefreshTokenModel(new RefreshTokenModel
                {
                    RefreshToken = refreshToken,
                    UserID = user.ID
                });

                return Ok(new LoginResponseModel { 
                    Token = token,
                    RefreshToken = refreshToken,
                    TokenExpired = DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds(),
                });
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized(new BaseResponseModel { ErrorMessage = "Invalid username or password" });
            }
        }
        [HttpGet("loginByRefeshToken")]
        public async Task<ActionResult<LoginResponseModel>> LoginByRefeshToken(string refreshToken)
        {
            try
            {
                var refreshTokenModel = await authService.GetRefreshTokenModel(refreshToken);
                var newToken = GenerateJwtToken(refreshTokenModel.User, isRefreshToken: false);
                var newRefreshToken = GenerateJwtToken(refreshTokenModel.User, isRefreshToken: true);

                await authService.AddRefreshTokenModel(new RefreshTokenModel
                {
                    RefreshToken = newRefreshToken,
                    UserID = refreshTokenModel.UserID
                });

                return new LoginResponseModel
                {
                    Token = newToken,
                    TokenExpired = DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds(),
                    RefreshToken = newRefreshToken,
                };
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized(new BaseResponseModel { ErrorMessage = "Invalid refresh token" });
            }
        }

        private string GenerateJwtToken(UserModel user, bool isRefreshToken)
        {
            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Username),
            };
            claims.AddRange(user.UserRoles.Select(n => new Claim(ClaimTypes.Role, n.Role.RoleName)));

            string secret = configuration.GetValue<string>($"Jwt:{(isRefreshToken ? "RefreshTokenSecret" : "Secret")}");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "doseHieu",
                audience: "doseHieu",
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(isRefreshToken ? 24*60 : 30),
                signingCredentials: creds
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
