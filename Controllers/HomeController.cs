using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using LoggedIn.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;

namespace LoggedIn.Controllers
{
    public class HomeController : Controller
    {
        private DashboardContext dbContext;
        public HomeController(DashboardContext context)
        {
            dbContext = context;
        }

        [HttpGet("")]
        public IActionResult Index()
        {

            return View();
        }

        // Create
        [HttpPost("create")]
        public IActionResult Create(DashboardUser user)
        {
            if(ModelState.IsValid)
            {
                if(dbContext.Users.Any(o => o.Email == user.Email))
                {
                    ModelState.AddModelError("Email", "Email already in use");
                    return View("Index");
                }

                PasswordHasher<DashboardUser> hasher = new PasswordHasher<DashboardUser>();
                user.Password = hasher.HashPassword(user, user.Password);

                var newUser = dbContext.Users.Add(user).Entity;
                dbContext.SaveChanges();

                HttpContext.Session.SetInt32("userId", newUser.UserId);
                HttpContext.Session.SetString("userName", newUser.FirstName);

                return RedirectToAction("Index", "Dashboard");
            }
            
            return View("Index");
        }
        [HttpPost("login")]
        public IActionResult Login(LoginUser user)
        {
            var test = dbContext.Users.ToList();
            if(ModelState.IsValid)
            {
                DashboardUser toLogin = dbContext.Users.FirstOrDefault(u => u.Email == user.EmailAttempt);
                if(toLogin == null)
                {
                    ModelState.AddModelError("EmailAttempt", "Invalid Email/Password");
                    return View("Index");
                }
                PasswordHasher<LoginUser> hasher = new PasswordHasher<LoginUser>();
                var result = hasher.VerifyHashedPassword(user, toLogin.Password, user.PasswordAttempt);
                if(result == PasswordVerificationResult.Failed)
                {
                    ModelState.AddModelError("EmailAttempt", "Invalid Email/Password");
                    return View("Index");
                }
                // Log user into session
                HttpContext.Session.SetInt32("userId", toLogin.UserId);
                HttpContext.Session.SetString("userName", toLogin.FirstName);
                return RedirectToAction("Index", "Dashboard");
            }
            return View("Index");
        }
        [HttpGet("logout")]
        public RedirectToActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Index");
        }
    }
}
