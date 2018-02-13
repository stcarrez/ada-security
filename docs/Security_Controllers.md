## Security Controller
The <b>Security.Controllers</b> package defines the security controller used to
verify that a given permission is granted.  A security controller uses the security
context and other controller specific and internal data to verify that the permission
is granted.

Security controller instances are created when the security policy rules are parsed.
These instances are shared across possibly several concurrent requests.

