<?php
require_once('../CSPGenerator.php');
// Automatically rewrite http:// url's to https:// url's when using https(HTTP over TLS/SSL).
CSPGenerator::getInstance()->setUpgradeInsecureRequests(true);
CSPGenerator::getInstance()->addImagesrc('upload.wikimedia.org');

// Set the headers, always call this method before any content output.
CSPGenerator::getInstance()->Parse();
// Start content output.
?><!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>example8 - Upgrade-insecure-requests</title>
	</head>
	<body>
<?php
$ishttps = false;
if (isset($_SERVER['HTTPS'])) {
    if ($_SERVER['HTTPS'] == 'on') {
        $ishttps = true;
    }
}

if ($ishttps) { ?>
		Image source url starts with http:// protocol handler but it's rewriten to the https:// protocol handler to load the image with https because of the <code>upgrade-insecure-requests</code> directive in the Content Security Policy header.<br />
		<img src="http://upload.wikimedia.org/wikipedia/commons/thumb/d/da/Internet2.jpg/320px-Internet2.jpg" alt="Image with http url will be loaded as https url.">
<?php } else { ?>
		<b>To test the Content Security Policy <code>Upgrade-insecure-requests</code> directive it's required to visit this page over https.</b>
<?php } ?>
	</body>
</html>
