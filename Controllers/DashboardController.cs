using System.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Session;
using Microsoft.EntityFrameworkCore;
using LoggedIn.Filters;
using LoggedIn.Models;

namespace LoggedIn.Controllers
{
    [Route("Dashboard")]
    [LoggedIn]
    public class DashboardController : Controller
    {
        private DashboardUser loggedInUser
        {
            get { return dbContext.Users.FirstOrDefault(u => u.UserId == HttpContext.Session.GetInt32("userId")); }
        } 
        private DashboardContext dbContext;
        public DashboardController(DashboardContext context)
        {
            dbContext = context;
        }
        // localhost:5000/Dashboards
        [HttpGet("")]
        public IActionResult Index()
        {
       

            return View();
        }
    }
}