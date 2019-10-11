using Microsoft.EntityFrameworkCore;

namespace LoggedIn.Models
{
    public class DashboardContext : DbContext
    {
        public DashboardContext(DbContextOptions options) : base(options) {}
        public DbSet<DashboardUser> Users {get;set;}
    }
}