using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Alumni22.Models;
using System.Security.Claims;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using Microsoft.Extensions.Logging;
using BCrypt.Net;

namespace Alumni22.Controllers
{
    public class AccountController : Controller
    {
        private readonly AlumniContext _db;
        private readonly ILogger<AccountController> _logger;

        public AccountController(AlumniContext db, ILogger<AccountController> logger)
        {
            _db = db;
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Login()
        {
            if (User.Identity.IsAuthenticated)
            {
                if (User.HasClaim("UserType", "Company"))
                {
                    return RedirectToAction("CompanyNeeds", "Home");
                }
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                var user = await _db.Users
                    .FirstOrDefaultAsync(u => u.Username == model.Username);

                if (user != null && VerifyPassword(model.Password, user.PasswordHash))
                {
                    await SignInUserAsync(user, model.RememberMe);

                    // Handle AJAX requests
                    if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                    {
                        return Json(new { success = true, redirectUrl = "/Home/Index" });
                    }

                    if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    {
                        return Redirect(returnUrl);
                    }

                    return RedirectToAction("Index", "Home");
                }

                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new { success = false, message = "Invalid login attempt" });
                }

                ModelState.AddModelError(string.Empty, "Invalid login attempt");
            }

            if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage);
                return Json(new { success = false, message = string.Join(", ", errors) });
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult Register()
        {
            if (User.Identity.IsAuthenticated)
            {
                if (User.HasClaim("UserType", "Company"))
                {
                    return RedirectToAction("CompanyNeeds", "Home");
                }
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                // Check if username is already taken
                if (await _db.Users.AnyAsync(u => u.Username == model.Username))
                {
                    if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                    {
                        return Json(new { success = false, message = "Username is already taken" });
                    }

                    ModelState.AddModelError("Username", "Username is already taken");
                    return View(model);
                }

                // Check if email is already in use
                if (await _db.Users.AnyAsync(u => u.Email == model.Email))
                {
                    if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                    {
                        return Json(new { success = false, message = "Email is already in use" });
                    }

                    ModelState.AddModelError("Email", "Email is already in use");
                    return View(model);
                }

                var user = new User
                {
                    Name = model.Name,
                    Username = model.Username,
                    Email = model.Email,
                    PasswordHash = HashPassword(model.Password),
                    RegisteredDate = DateTime.UtcNow
                };

                _db.Users.Add(user);
                await _db.SaveChangesAsync();

                await SignInUserAsync(user, false);

                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new { success = true, redirectUrl = "/Home/Index" });
                }

                return RedirectToAction("Index", "Home");
            }

            if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage);
                return Json(new { success = false, message = string.Join(", ", errors) });
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult CompanyLogin()
        {
            if (User.Identity.IsAuthenticated)
            {
                if (User.HasClaim("UserType", "Company"))
                {
                    return RedirectToAction("CompanyNeeds", "Home");
                }
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CompanyLogin(CompanyLoginViewModel model, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                var company = await _db.Companies
                    .FirstOrDefaultAsync(c => c.Username == model.Username);

                if (company != null && VerifyPassword(model.Password, company.PasswordHash))
                {
                    await SignInCompanyAsync(company, model.RememberMe);

                    if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                    {
                        return Json(new { success = true, redirectUrl = "/Home/CompanyNeeds" });
                    }

                    if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    {
                        return Redirect(returnUrl);
                    }

                    return RedirectToAction("CompanyNeeds", "Home");
                }

                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new { success = false, message = "Invalid login attempt" });
                }

                ModelState.AddModelError(string.Empty, "Invalid login attempt");
            }

            if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage);
                return Json(new { success = false, message = string.Join(", ", errors) });
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult CompanyRegister()
        {
            if (User.Identity.IsAuthenticated)
            {
                if (User.HasClaim("UserType", "Company"))
                {
                    return RedirectToAction("CompanyNeeds", "Home");
                }
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CompanyRegister(CompanyRegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                // Check if username is already taken (by either user or company)
                if (await _db.Companies.AnyAsync(c => c.Username == model.Username) ||
                    await _db.Users.AnyAsync(u => u.Username == model.Username))
                {
                    if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                    {
                        return Json(new { success = false, message = "Username is already taken" });
                    }

                    ModelState.AddModelError("Username", "Username is already taken");
                    return View(model);
                }

                if (await _db.Companies.AnyAsync(c => c.Email == model.Email))
                {
                    if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                    {
                        return Json(new { success = false, message = "Email is already in use" });
                    }

                    ModelState.AddModelError("Email", "Email is already in use");
                    return View(model);
                }

                var company = new Company
                {
                    Name = model.Name,
                    Username = model.Username,
                    Email = model.Email,
                    PasswordHash = HashPassword(model.Password),
                    Industry = model.Industry,
                    ContactPerson = model.ContactPerson,
                    PhoneNumber = model.PhoneNumber,
                    RegisteredDate = DateTime.UtcNow
                };

                _db.Companies.Add(company);
                await _db.SaveChangesAsync();

                await SignInCompanyAsync(company, false);

                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new { success = true, redirectUrl = "/Home/CompanyNeeds" });
                }

                return RedirectToAction("CompanyNeeds", "Home");
            }

            if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage);
                return Json(new { success = false, message = string.Join(", ", errors) });
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            _logger.LogInformation($"User {User.Identity.Name} logging out at {DateTime.UtcNow}");

            try
            {
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                foreach (var cookie in Request.Cookies.Keys)
                {
                    if (cookie.StartsWith(".AspNetCore") ||
                        cookie.Contains("Authentication") ||
                        cookie.Contains("Cookies"))
                    {
                        Response.Cookies.Delete(cookie);
                    }
                }

                TempData["LogoutMessage"] = "You have been successfully logged out.";

                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new
                    {
                        success = true,
                        redirectUrl = Url.Action("Default", "Home"),
                        message = "Logged out successfully"
                    });
                }

                return RedirectToAction("Default", "Home");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error during logout for user {User.Identity.Name}");

                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new
                    {
                        success = false,
                        message = "An error occurred during logout"
                    });
                }

                return RedirectToAction("Default", "Home");
            }
        }

        [HttpGet]
        public IActionResult IsAuthenticated()
        {
            return Json(new
            {
                isAuthenticated = User.Identity.IsAuthenticated,
                userName = User.Identity.IsAuthenticated ? User.FindFirst("FullName")?.Value : null,
                userType = User.Identity.IsAuthenticated && User.HasClaim("UserType", "Company") ? "Company" : "User"
            });
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        #region Helper Methods
        private async Task SignInUserAsync(User user, bool isPersistent)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim("FullName", user.Name),
                new Claim("Username", user.Username),
                new Claim("UserType", "User")
            };

            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var authProperties = new AuthenticationProperties
            {
                IsPersistent = isPersistent,
                ExpiresUtc = isPersistent ? DateTimeOffset.UtcNow.AddDays(7) : DateTimeOffset.UtcNow.AddMinutes(20)
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);
        }

        private async Task SignInCompanyAsync(Company company, bool isPersistent)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, company.Username),
                new Claim(ClaimTypes.NameIdentifier, company.Id.ToString()),
                new Claim("FullName", company.Name),
                new Claim("Username", company.Username),
                new Claim("UserType", "Company")
            };

            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var authProperties = new AuthenticationProperties
            {
                IsPersistent = isPersistent,
                ExpiresUtc = isPersistent ? DateTimeOffset.UtcNow.AddDays(7) : DateTimeOffset.UtcNow.AddMinutes(20)
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);
        }

        private string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        private bool VerifyPassword(string password, string storedHash)
        {
            return BCrypt.Net.BCrypt.Verify(password, storedHash);
        }
        #endregion
    }
}