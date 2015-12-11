using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;

namespace QuickStart
{
    public class RouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");

            #region Error Routes
            routes.MapRoute(
              name: "Forbidden",
              url: "Error/Forbidden",
              defaults: new { controller = "Error", action = "UnAuthorized" }
          );

            #endregion



            #region Account Routes

            routes.MapRoute(
              name: "RegisterAccount",
              url: "Account/Register",
              defaults: new { controller = "Account", action = "Register" }
          );

            routes.MapRoute(
                name: "ForgotPassword",
                url: "Account/ForgotPassword",
                defaults: new { controller = "Account", action = "ForgotPassword" }
            );

            #endregion

            routes.MapRoute(
                name: "Default",
                url: "{controller}/{action}/{id}",
                defaults: new { controller = "Home", action = "Index", id = UrlParameter.Optional }
            );
        }
    }
}
