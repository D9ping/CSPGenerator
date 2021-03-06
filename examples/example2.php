<?php
require_once('../CSPGenerator.php');
// Allow images from files.phpclasses.org on any protocol(https,http,ftp but not from base64 data uri).
CSPGenerator::getInstance()->addImagesrc('files.phpclasses.org');

// Set the headers, always call this method before any content output.
CSPGenerator::getInstance()->Parse();
// Start content output.
?><!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>example2 - allow image to load</title>
	</head>
	<body>
		<!-- The elePHPant from PHPClasses.org should be allowed to load -->
		<p><img src="https://files.phpclasses.org/graphics/phpclasses/elephpant.png" alt="BAD, this image should not be blocked" /></p>
		<!-- The following image should be blocked/not showed
		because it's not a whitelisted source in the CSP header. -->
		<p><img src="https://upload.wikimedia.org/wikipedia/commons/3/32/Notgood.png" alt="OK, image blocked" /></p>
	</body>
</html>
