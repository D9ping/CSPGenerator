<?php
require_once('../CSPGenerator.php');

// Using CSPGenerator as a normal class instead of a singleton is possible.
// Now you should make sure yourself that you are not creating an additional instance of the class.
$cspGenerator = new CSPGenerator();

$cspGenerator->addStylesrc("'unsafe-inline'");
// Set the headers, always call this method before any content output.
$cspGenerator->Parse();
// Start content output.
?><!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>example1 - allow (unsafe)inline css</title>
	</head>
	<body>
		<!-- The following text is allowed to be centred because 'unsafe-inline' is added the CSP header. -->
		<p style="text-align: center">testing inline css use</p>
	</body>
</html>
