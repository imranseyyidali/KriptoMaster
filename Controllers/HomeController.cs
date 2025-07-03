using Microsoft.AspNetCore.Mvc;

namespace SifrelemeProjesi.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
