<?php
require_once('CSPGenerator.php');

// Allow use of AJAX to same origin.
CSPGenerator::getInstance()->addConnectsrc("'self'");
// Allow use of inline JavaScript. (Not recommended because doing this will not defeat the script 
// in common JavaScript injections from running. But having other limited directives e.g. 
// connect-src and default-src none, can still prevent some damage.)
CSPGenerator::getInstance()->addScriptsrc("'unsafe-inline'");


// Set the headers, always call this method before any content output.
CSPGenerator::getInstance()->Parse();
if (!empty(filter_input(INPUT_GET, 'getresponse'))) {
    header('X-Content-Type-Options: nosniff');
    header('Content-type: text/xml; charset=utf-8');
    echo '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' . "\r\n";
    echo '<response>Okay</response>';
} else {
?><!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>example3</title>
    </head>
    <body>

        <div id="result">..</div>

        <script type="text/javascript">
var xmlhttp = new XMLHttpRequest();
xmlhttp.onreadystatechange = function() {
    if (xmlhttp.readyState === 4 && xmlhttp.status === 200) {
        var xmldoc = xmlhttp.responseXML;
        document.getElementById("result").textContent = xmldoc.getElementsByTagName("response")[0].textContent;
    }
}

xmlhttp.open('GET', 'example3.php?getresponse=1', true);
xmlhttp.send();
        </script>

    </body>
</html><?php
}