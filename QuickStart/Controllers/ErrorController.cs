﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace AffiliateHub.Controllers
{
    public class ErrorController : Controller
    { 

        // GET: UnAuthorize
        public ActionResult UnAuthorized()
        {
            return View();
        }

       
    }
}