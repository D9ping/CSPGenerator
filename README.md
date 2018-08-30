# CSPGenerator
CSPGenerator is a singleton PHP Class to generate the Content Security Policy HTTP header,
and other security HTTP headers related to the Content Security Policy HTTP header supported by the user-agent.
The class will take care of sending the supported Content Security Policy HTTP header to the user-agent.
E.g. if the user-agent only supports the decreated X-Content-Security-Policy header because the visitor is using a old version of Firefox. The CSPGenerator class will make sure the only sends the  X-Content-Security-Policy header with the supported Content Security Policy directives.

### how to use the CSPGenerator?
Simply add the following line to the top of your file:
require_once('CSPGenerator.php');

Then to generate the default restrictive Content Security Policy HTTP header
add the following line just before you sending any content to the client.
CSPGenerator::getInstance()->Parse();

To learn more about how to add Content Security Policy directives to relax the default restrictive content security policy [see the examples](examples).

### Support
If you find CSPGenerator useful consider donating:
[![Beerpay](https://beerpay.io/D9ping/CSPGenerator/badge.svg)](https://beerpay.io/D9ping/CSPGenerator)
