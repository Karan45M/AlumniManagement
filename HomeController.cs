using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Alumni22.Models;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using System.Reflection.PortableExecutable;
using System.Text.RegularExpressions;


using System.Threading.Tasks;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.parser;

using Microsoft.AspNetCore.Hosting;
using System.Linq;
using Microsoft.EntityFrameworkCore;




namespace Alumni22.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    public static List<Front> Fronts = new List<Front>();
    AlumniContext context;
    private readonly IWebHostEnvironment _env;
    public HomeController(ILogger<HomeController> logger,AlumniContext A1)
    {
        _logger = logger;
        context = A1;
        if (!context.BotResponses.Any())
        {
            context.BotResponses.AddRange(
                new BotResponse { ActionId = "class-schedule", ResponseText = "Here is your class schedule: ..." },
                new BotResponse { ActionId = "view-grades", ResponseText = "Here are your current grades: ..." },
                new BotResponse { ActionId = "course-registration", ResponseText = "Course registration starts soon." },
                new BotResponse { ActionId = "exam-schedule", ResponseText = "Your final exam schedule is: ..." },
                new BotResponse { ActionId = "financial-aid", ResponseText = "You have a scholarship and federal grant." }
            );
            context.SaveChanges(); // Save to DB
        }



    }

    [HttpPost]
    public IActionResult responses()
    {
        var data = context.BotResponses.ToDictionary(x => x.ActionId, x => x.ResponseText);
        return Json(data);
    }

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult AdminDashboard()
    {
        var dashboardStats = new AdminDashboardViewModel
        {
            TotalAlumni = GetTotalAlumniCount(),
            ActiveEvents = GetActiveEventsCount(),
            JobPostings = GetJobPostingsCount(),
            NewRegistrations = GetNewRegistrationsCount(),
            // Convert database models to view model
            RecentAlumnis = context.Alumni
                .OrderByDescending(a => a.CreatedAt)
                .Take(5)
                .Select(a => new AdminDashboardViewModel.Alumni
                {
                    Id = a.Id,
                    FullName = a.FullName,
                    RegistrationNumber = a.RegistrationNumber,
                    Email = a.Email,
                    GraduationYear = a.GraduationYear,
                    Degree = a.Degree,
                    CurrentJobTitle = a.CurrentJobTitle,
                    CurrentCompany = a.CurrentCompany,
                    CreatedAt = a.CreatedAt,
                    Status = a.Status
                })
                .ToList(),
            RecentJobPostings = context.Jobs
                .OrderByDescending(j => j.PostedDate)
                .Take(5)
                .Select(j => new AdminDashboardViewModel.JobPosting
                {
                    Id = j.Id,
                    JobTitle = j.JobTitle,
                    Description = j.Description,
                    PostedDate = j.PostedDate,
                    Company = j.Company,
                    Status = j.Status
                })
                .ToList(),
            UpcomingEvents = context.Events
                .Where(e => e.EventDate > DateTime.Now)
                .OrderBy(e => e.EventDate)
                .Take(5)
                .Select(e => new AdminDashboardViewModel.Event
                {
                    Id = e.Id,
                    EventName = e.EventName,
                    EventDate = e.EventDate,
                    Location = e.Location,
                    Registrations = e.Registrations,
                    Status = e.Status
                })
                .ToList()
        };

        return View(dashboardStats);
    }

    public ActionResult AdminEventList()
    {
        return View();
    }

    public ActionResult Alumni()
    {


        return View();
    }

    public ActionResult Analytics()
    {

        return View();
    }
    public ActionResult    Bio()
    {
   return     View();

    }

    public ActionResult Jobs()
    { 

        return View();
    }
    public ActionResult Job()
    {

        return View();
    }
    public ActionResult Event()
    {

        return View();
    }


    public ActionResult AdminAlumniList()
    {
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    // Login Action
    [HttpPost]
    public JsonResult Login([FromBody] Credential credentials)
    {
        // Validate input
        if (string.IsNullOrWhiteSpace(credentials.Email) || string.IsNullOrWhiteSpace(credentials.Password))
        {
            return Json(new { success = false, message = "Email and password are required." });
        }

        try
        {
            // Hash the provided password
            var hashedPassword = HashPassword(credentials.Password);

            // Find user by email and hashed password
            var user = context.Credentials.FirstOrDefault(c =>
                c.Email == credentials.Email && c.Password == hashedPassword);

            if (user != null)
            {
                // Consider adding additional security measures like:
                // - Generating an authentication token
                // - Setting up session management
                return Json(new { success = true, message = "Login successful!" });
            }
            else
            {
                // Use a generic message to prevent email enumeration
                return Json(new { success = false, message = "Invalid login credentials." });
            }
        }
        catch (Exception ex)
        {
            // Log the exception (in a real-world scenario)
            return Json(new { success = false, message = "An error occurred during login." });
        }
    }

    // Signup Action
    [HttpPost]
    public JsonResult SignUp([FromBody] Credential credentials)
    {
        if (context.Credentials.Any(c => c.Email == credentials.Email))
        {
            return Json(new { success = false, message = "Email already exists." });
        }

        // Ensure Fullname is not null or empty
        if (string.IsNullOrWhiteSpace(credentials.Fullname))
        {
            return Json(new { success = false, message = "Full name is required." });
        }

        credentials.Password = HashPassword(credentials.Password);

        try
        {
            context.Credentials.Add(credentials);
            context.SaveChanges();
            return Json(new { success = true, message = "Signup successful!" });
        }
        catch (Exception ex)
        {
            // Log the exception
            return Json(new { success = false, message = "An error occurred during signup." });
        }
    }

    // Password Encryption
    private string HashPassword(string password)
    {
        using (var sha256 = SHA256.Create())
        {
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
        }
    }



    // Dashboard Statistics Methods
    private int GetTotalAlumniCount()
    {
        return context.Alumni.Count();
    }

    private int GetActiveEventsCount()
    {
        return context.Events.Count(e => e.EventDate > DateTime.Now);
    }

    private int GetJobPostingsCount()
    {
        // Assuming you have a JobPosting model
        return context.Jobs.Count();
    }

    private int GetNewRegistrationsCount()
    {
        // Count registrations in the last 30 days
        var thirtyDaysAgo = DateTime.Now.AddDays(-30);
        return context.Alumni.Count(a => a.CreatedAt >= thirtyDaysAgo);
    }

    private List<Alumni> GetRecentAlumni()
    {
        return context.Alumni
            .OrderByDescending(a => a.CreatedAt)
            .Take(5)
            .ToList();
    }

    private List<Job> GetRecentJobPostings()
    {
        return context.Jobs
            .OrderByDescending(j => j.PostedDate)
            .Take(5)
            .ToList();
    }

    private List<Event> GetUpcomingEvents()
    {
        return context.Events
            .Where(e => e.EventDate > DateTime.Now)
            .OrderBy(e => e.EventDate)
            .Take(5)
            .ToList();
    }

    [HttpPost]
    public JsonResult EditAlumni(Alumni A1)
    {

        var alumni = context.Alumni.FirstOrDefault(e => e.RegistrationNumber == A1.RegistrationNumber);
        alumni.FullName = A1.FullName;
        alumni.RegistrationNumber = A1.RegistrationNumber;
        alumni.Email = A1.Email;
        alumni.PhoneNumber = A1.PhoneNumber;
        alumni.Address = A1.Address;
        alumni.GraduationYear = A1.GraduationYear;
        alumni.Degree = A1.Degree;
        alumni.CurrentJobTitle = A1.CurrentJobTitle;
        alumni.CurrentCompany = A1.CurrentCompany;
        context.SaveChanges();
        return Json(new { success = true, message = "Update successful!", data = alumni });

    }

    public JsonResult DeleteAlumni(Alumni A1)
    {
        var alumni = context.Alumni.FirstOrDefault(e => e.RegistrationNumber == A1.RegistrationNumber);
        context.Alumni.Remove(alumni);
        context.SaveChanges();
        return Json(new { success = true, message = "Update successful!", data = alumni });

    }

    [HttpPost]
    public JsonResult EditEvent(Event E1)
    {


        var Event = context.Events.FirstOrDefault(e => e.EventId == E1.EventId);
        Event.EventName = E1.EventName;
        Event.EventId = E1.EventId;
        Event.EventDate = E1.EventDate;
        Event.Location = E1.Location;
        Event.Description = E1.Description;
        context.SaveChanges();
        return Json(new { success = true, message = "Event updated successfully!" });


    }

    [HttpPost]
    public JsonResult DeleteEvent(Event E1)
    {
        var Event = context.Events.FirstOrDefault(e => e.EventId == E1.EventId);
        context.Events.Remove(E1);
        context.SaveChanges();
        return Json(new { success = true, message = "Event deleted successfully!" });

    }




   // [Authorize(Policy = "UserOnly")]
    public IActionResult UploadResume()
    {
        return View();
    }

    [HttpPost]
   // [Authorize(Policy = "UserOnly")]
    public async Task<IActionResult> ResumeUpload(IFormFile Resume, Front CC)
    {
        if (Resume == null || Resume.Length == 0)
        {
            ModelState.AddModelError("Resume", "Please select a file to upload");
            return View("UploadResume");
        }

        context.Fronts.Add(CC);
        await context.SaveChangesAsync();

        var username = User.FindFirst("Username")?.Value;
        var baseDirectory = System.IO.Path.Combine(_env.WebRootPath, "Resume");
        if (!System.IO.Directory.Exists(baseDirectory))
        {
            System.IO.Directory.CreateDirectory(baseDirectory);
        }

        var userDirectory = System.IO.Path.Combine(baseDirectory, username);
        if (!System.IO.Directory.Exists(userDirectory))
        {
            System.IO.Directory.CreateDirectory(userDirectory);
        }

        var filePath = System.IO.Path.Combine(userDirectory, Resume.FileName);

        using (var s = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize: 4096, useAsync: true))
        {
            await Resume.CopyToAsync(s);
        }

        string resumeText = ExtractDataFromPdf(filePath);
        var companyRequirements = await context.CompanyRequirements.ToListAsync();

        if (companyRequirements.Count == 0)
        {
            companyRequirements = new List<CompanyRequirement>
                {
                    new CompanyRequirement { CompanyName = "Tech Solutions", JobDescription = "Experience with .NET and ASP.NET.", SkillsRequired = "C#, .NET, ASP.NET", Salary = 90000, Location = "New York", Deadline = DateTime.Now.AddDays(30), Experience = 3 },
                    new CompanyRequirement { CompanyName = "DataCorp", JobDescription = "Knowledge of Python and data analysis.", SkillsRequired = "Python, SQL, Machine Learning", Salary = 95000, Location = "San Francisco", Deadline = DateTime.Now.AddDays(45), Experience = 2 },
                    new CompanyRequirement { CompanyName = "WebWorks", JobDescription = "Proficient in HTML, CSS, and JavaScript.", SkillsRequired = "HTML, CSS, JavaScript", Salary = 80000, Location = "Remote", Deadline = DateTime.Now.AddDays(60), Experience = 1 }
                };
        }

        var matchedResults = new List<MatchedResult>();

        foreach (var c in companyRequirements)
        {
            double matchScore = CalculateMatch(resumeText, c.JobDescription);
            matchedResults.Add(new MatchedResult
            {
                CompanyRequirement = c,
                MatchScore = matchScore
            });
        }

        return View("MatchedResults", matchedResults);
    }

  //  [Authorize(Policy = "UserOnly")]
    public async Task<IActionResult> MatchedResult()
    {
        var username = User.FindFirst("Username")?.Value;
        var resumePath = System.IO.Directory.GetFiles(System.IO.Path.Combine(_env.WebRootPath, "Resume", username), "*.pdf").FirstOrDefault();

        if (string.IsNullOrEmpty(resumePath) || !System.IO.File.Exists(resumePath))
        {
            TempData["Error"] = "Please upload a resume first.";
            return RedirectToAction("UploadResume");
        }

        string resumeText = ExtractDataFromPdf(resumePath);
        var companyRequirements = await context.CompanyRequirements.ToListAsync();

        if (companyRequirements.Count == 0)
        {
            companyRequirements = new List<CompanyRequirement>
                {
                    new CompanyRequirement { CompanyName = "Tech Solutions", JobDescription = "Experience with .NET and ASP.NET.", SkillsRequired = "C#, .NET, ASP.NET", Salary = 90000, Location = "New York", Deadline = DateTime.Now.AddDays(30), Experience = 3 },
                    new CompanyRequirement { CompanyName = "DataCorp", JobDescription = "Knowledge of Python and data analysis.", SkillsRequired = "Python, SQL, Machine Learning", Salary = 95000, Location = "San Francisco", Deadline = DateTime.Now.AddDays(45), Experience = 2 },
                    new CompanyRequirement { CompanyName = "WebWorks", JobDescription = "Proficient in HTML, CSS, and JavaScript.", SkillsRequired = "HTML, CSS, JavaScript", Salary = 80000, Location = "Remote", Deadline = DateTime.Now.AddDays(60), Experience = 1 }
                };
        }

        var matchedResults = new List<MatchedResult>();

        foreach (var c in companyRequirements)
        {
            double matchScore = CalculateMatch(resumeText, c.JobDescription);
            matchedResults.Add(new MatchedResult
            {
                CompanyRequirement = c,
                MatchScore = matchScore
            });
        }

        return View("MatchedResults", matchedResults);
    }

    public string ExtractDataFromPdf(string f)
    {
        using PdfReader reader = new PdfReader(f);
        StringBuilder text = new StringBuilder();
        for (int i = 1; i <= reader.NumberOfPages; i++)
        {
            text.Append(PdfTextExtractor.GetTextFromPage(reader, i));
        }
        return text.ToString();
    }

    public double CalculateMatch(string resumeText, string jobDescription)
    {
        var resumeWords = new HashSet<string>(Regex.Split(resumeText.ToLower(), @"\W+"));
        var jobWords = new HashSet<string>(Regex.Split(jobDescription.ToLower(), @"\W+"));
        var matchedWords = resumeWords.Intersect(jobWords).Count();
        return (double)matchedWords / jobWords.Count;
    }

    [HttpGet]
    //[Authorize(Policy = "CompanyOnly")]
    public IActionResult CompanyNeeds()
    {
        return View();
    }

    [HttpPost]
   // [Authorize(Policy = "CompanyOnly")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CompanyNeeds(CompanyRequirement c)
    {
        _logger.LogInformation("Attempting to post new job requirement: {@CompanyRequirement}", c);

        if (ModelState.IsValid)
        {
            try
            {
                c.CompanyName = User.FindFirst("FullName")?.Value;
                _logger.LogInformation("Assigning CompanyName: {CompanyName}", c.CompanyName);

                context.CompanyRequirements.Add(c);
                await context.SaveChangesAsync();
                _logger.LogInformation("Job requirement saved successfully with ID: {Id}", c.id);

                if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
                {
                    return Json(new { success = true, redirectUrl = Url.Action("CompanyRequirement") });
                }

                return RedirectToAction("CompanyRequirement");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving job requirement: {@CompanyRequirement}", c);
                ModelState.AddModelError(string.Empty, "An error occurred while saving the job requirement.");
                return View(c);
            }
        }

        _logger.LogWarning("Model state is invalid: {@ModelState}", ModelState);
        if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
        {
            var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage);
            return Json(new { success = false, message = string.Join(", ", errors) });
        }

        return View(c);
    }

  //  [Authorize]
    public async Task<IActionResult> CompanyRequirement()
    {
        var companyRequirements = await context.CompanyRequirements.ToListAsync();
        _logger.LogInformation("Retrieved {Count} company requirements", companyRequirements.Count);
        return View(companyRequirements);
    }









}




