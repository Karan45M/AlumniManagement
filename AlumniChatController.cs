using Alumni22.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Alumni22.Controllers
{
    public class AlumniChatController : Controller
    {
        private readonly AlumniContext _context;
        AlumniContext context;
        public AlumniChatController(AlumniContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> Index()
        {


            var alumni = await _context.Alumni
                .OrderBy(u => u.FullName)
                .ToListAsync();

            return View(alumni); // ✅ Wrap with View() to return IActionResult
        }


        [HttpGet]
        public async Task<IActionResult> GetConversation(string alumniId)
        {
            int? currentUserId = HttpContext.Session.GetInt32("AlumniId");

            // Optional: comment this out if not simulating login
            if (currentUserId == null)
            {
                return Unauthorized();
            }

            int otherUserId = int.Parse(alumniId);

            var messages = await _context.AlumniChatMessages
                .Where(m => (m.SenderId == currentUserId && m.ReceiverId == otherUserId) ||
                            (m.SenderId == otherUserId && m.ReceiverId == currentUserId))
                .OrderBy(m => m.SentDateTime)
                .Include(m => m.Sender)
                .Include(m => m.Receiver)
                .Select(m => new
                {
                    Id = m.Id,
                    SenderId = m.SenderId,
                    SenderName = m.Sender.FullName,
                    ReceivedId = m.ReceiverId,
                    Content = m.Content,
                    SentDateTime = m.SentDateTime.ToString("g"),
                    IsRead = m.IsRead
                })
                .ToListAsync();

            return Json(messages);
        }

        [HttpGet]
        public async Task<IActionResult> GetUnreadMessagesCount()
        {
            int? currentUserId = HttpContext.Session.GetInt32("AlumniId");

            if (currentUserId == null)
            {
                return Json(0);
            }

            var count = await _context.AlumniChatMessages
                .CountAsync(m => m.ReceiverId == currentUserId && !m.IsRead);

            return Json(count);
        }
    }
}
