<?php
require_once('CSPGenerator.php');
// Allow use of style="..." iniline CSS.
CSPGenerator::getInstance()->addStylesrc("'unsafe-inline'");


// Set the headers, always call this method before any content output.
CSPGenerator::getInstance()->Parse();
// Start content output.
?><!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>example1</title>
    </head>
    <body>
        <!-- The following text is allowed to be centred because 'unsafe-inline' is added the CSP header. -->
        <p style="text-align: center">testing iniline css</p>
    </body>
</html>