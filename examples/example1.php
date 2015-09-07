<?php
require_once('../CSPGenerator.php');
// Allow use of style="..." inline CSS.
// Unsafe because can be a css inject can then control how the page looks.
CSPGenerator::getInstance()->addStylesrc("'unsafe-inline'");
// To avoid this it's recommended to use a stylesheets file instead and use classes and id's only in html.


// Set the headers, always call this method before any content output.
CSPGenerator::getInstance()->Parse();
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
