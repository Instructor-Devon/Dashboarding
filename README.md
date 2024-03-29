# Login Dashboard
#### Uses `ActionFilterAttribute` to set ViewBag.Username when user is logged in and redirects to Login/Reg page when user is not.
---
### LoggedInAttribute
```cs
public class LoggedInAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        // Assumes these session properties are set upon login/reg
        var uId = context.HttpContext.Session.GetInt32("userId");
        var uName = context.HttpContext.Session.GetString("userName");
        
        if(uId == null)
        {
            // If no user in session, redirect to home page
            context.Result = new RedirectToActionResult("Index", "Home", null);
        }
        else
        {
            // Otherwise set ViewBag
            ((Controller)context.Controller).ViewBag.Username = uName;
        }
    }

}
```
### DashboardController (Usage)
```cs

// Used on the controller class, all Actions in the class will either 
// get ViewBag.Username, or user will get redirected
[LoggedIn]

public class DashboardController : Controller
{
    private DashboardUser loggedInUser
    {
        get { return dbContext.Users.FirstOrDefault(u => u.UserId == HttpContext.Session.GetInt32("userId")); }
    } 
    private DashboardContext dbContext;
    public DashboardController(DashboardContext context, ISessionStore sesh)
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
```