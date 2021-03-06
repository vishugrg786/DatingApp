using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;


namespace DatingApp.API.Controllers

{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;
        private readonly IMapper _mapper;

        public AuthController(IAuthRepository repo, IConfiguration config, IMapper mapper)
        {
            _config = config;
            _mapper = mapper;
            _repo = repo;

        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {

            //validate the request

            userForRegisterDto.Username = userForRegisterDto.Username.ToLower();
            if (await _repo.UserExists(userForRegisterDto.Username))
                return BadRequest("username already exists");

            var userToCreate = _mapper.Map<User>(userForRegisterDto);

            var createdUser = await _repo.Register(userToCreate, userForRegisterDto.Password);
            var userToReturn = _mapper.Map<UserForDetailedDto>(createdUser);

            return CreatedAtRoute("GetUser", new {Controller = "Users", 
            id=createdUser.Id },userToReturn );
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            var userFromRepo = await _repo.Login(userForLoginDto.UserName.ToLower(), userForLoginDto.Password);

            if (userFromRepo == null)
                return Unauthorized();

            //Here we will start building our token
            // for claims bring the system.security.claims and it will be an array
            var claims = new[]{
              new Claim(ClaimTypes.NameIdentifier,userFromRepo.Id.ToString()),
              new Claim(ClaimTypes.Name,userFromRepo.Username)
          };

          //IN order to make sure that our tokens are valid tokens when it comes back , server needs to
          //verify this token so we are generating the key and using to sign the credentials

            // we will also need a key to sign into our token and it will be hashed and 
            // for symmetricsecuritytoken bring the system.identitymodels.tokens and encode into byte
            // we will store it into config file.
            var key=new SymmetricSecurityKey(Encoding.UTF8
             .GetBytes(_config.GetSection("AppSettings:Token").Value));
            
            //now we have the key so we can generate signing credentials and signingCredentials 
            //takes the key that we generated and the algo which will hash this key  
            var creds=new SigningCredentials(key,SecurityAlgorithms.HmacSha512Signature);

            //now we need a security token descriptor which is going to take the claim,
            //expiry date for our token and the signing credentials
            var tokenDescriptor=new SecurityTokenDescriptor{
                Subject=new ClaimsIdentity(claims),
                Expires=DateTime.Now.AddDays(1),
                SigningCredentials=creds
            };

            // we will also need a tokenhandler as well
            var tokenHandler=new JwtSecurityTokenHandler();
            var token=tokenHandler.CreateToken(tokenDescriptor); 
            
            var user=_mapper.Map<UserForListDto>(userFromRepo);

            return Ok(new{
                token=tokenHandler.WriteToken(token),
                user
            });

           
        }

    }
}