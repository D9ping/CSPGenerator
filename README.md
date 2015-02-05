# CSPGenerator
CSPGenerator is a singleton PHP Class to generate the Content Security Policy HTTP headers,
and other security HTTP headers. 
This class will try to set the supported HTTP security headers of the useragent.
The headers the class can are: Content-Security-Policy, Content-Security-Policy-Report-Only, 
X-Content-Security-Policy-Report-Only, X-Content-Security-Policy, X-WebKit-CSP-Report-Only, 
X-WebKit-CSP, X-Frame-Options and X-XSS-Protection header.