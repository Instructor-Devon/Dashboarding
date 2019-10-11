using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using LoggedIn.Models;
using System.Linq;

namespace LoggedIn.Filters
{
public class LoggedInAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        var uId = context.HttpContext.Session.GetInt32("userId");
        var uName = context.HttpContext.Session.GetString("userName");
        if(uId == null)
        {
            context.Result = new RedirectToActionResult("Index", "Home", null);
        }
        else
        {
            ((Controller)context.Controller).ViewBag.Username = uName;
        }
    }

}
}