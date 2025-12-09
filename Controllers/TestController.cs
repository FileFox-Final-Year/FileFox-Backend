using Microsoft.AspNetCore.Mvc;

namespace FileFox_Backend.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TestController : ControllerBase
    {
        [HttpGet("test-error")]
        public IActionResult ThrowError()
        {
            // This will simulate a server error
            throw new Exception("This is a test exception for global middleware.");
        }
    }
}