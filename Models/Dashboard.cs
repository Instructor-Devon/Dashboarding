using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace LoggedIn.Models
{
    public class Dashboard
    {
        [Key]
        public int DashboardId {get;set;}
        public string Groom {get;set;}
        public string Bride {get;set;}
        // Must Be Future Date
        [DataType(DataType.Date)]
        [FutureDate]
        public DateTime Date {get;set;}
        public string Address {get;set;}
        public int UserId {get;set;}
        public DashboardUser Planner {get;set;}
        public List<Response> Responses {get;set;}
    }
    public class Response
    {
        [Key]
        public int ResponseId {get;set;}
        public int DashboardId {get;set;}
        public int UserId {get;set;}
        public DashboardUser Guest {get;set;}
    }
    

}