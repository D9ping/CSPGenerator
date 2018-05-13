<?php
require_once('../CSPGenerator.php');

// Allow use of AJAX requests to same origin.
CSPGenerator::getInstance()->addConnectsrc("'self'");
CSPGenerator::getInstance()->addScriptsrc("'self'");


// Set the headers, always call this method before any content output.
CSPGenerator::getInstance()->Parse();
if (!empty(filter_input(INPUT_GET, 'getresponse'))) {
    header('X-Content-Type-Options: nosniff');
    header('Content-type: text/xml; charset=utf-8');
    echo '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'."\r\n";
    echo '<response>Okay</response>'."\r\n";
} else {
?><!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>example3 - allow ajax requests to same orgin</title>
	</head>
	<body>
		<div id="result"><noscript>JavaScript not enabled.</noscript></div>
		<script type="application/javascript" src="./example3.js"></script>
	</body>
</html>
<?php
}
