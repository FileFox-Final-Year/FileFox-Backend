using Microsoft.AspNetCore.Mvc;

namespace FileFox_Backend.Controllers
{
    [ApiController]
    [Route("hello")]
    public class HelloController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("Hello World from FileFox Backend!");
        }
    }
}