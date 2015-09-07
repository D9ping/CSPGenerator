<?php
require_once('../CSPGenerator.php');

// E.g. allow inline google analytics javascript snippet.
// The following javascript code needs hashed before the Content Security Policy
// HTTP header is send to the client.
$jscode = "
  var _gaq = _gaq || [];
  _gaq.push(['_setAccount', 'UA-XXXXXXXX']);
  _gaq.push(['_trackPageview']);
  (function() {
    var ga = document.createElement('script');
    ga.type = 'text/javascript';
    ga.async = true;
    ga.src = ('https:' == document.location.protocol ? 'https://ssl' : 'http://www') + '.google-analytics.com/ga.js';
    var s = document.getElementsByTagName('script')[0];
    s.parentNode.insertBefore(ga, s);
  })();

  alert('Google analytics snippet loaded.');
";

CSPGenerator::getInstance()->addScriptsrcHash($jscode, 'sha384');
CSPGenerator::getInstance()->addScriptsrc('https://ssl.google-analytics.com');
CSPGenerator::getInstance()->addScriptsrc('http://www.google-analytics.com');
CSPGenerator::getInstance()->addImagesrc('https://ssl.google-analytics.com');
CSPGenerator::getInstance()->addImagesrc('http://www.google-analytics.com');

// Set the headers, always call this method before any content output.
CSPGenerator::getInstance()->Parse();
// Start content output.
?><!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>example6 - allow inline script with hash</title>
	</head>
	<body>
	<!-- Whitelisted inline script: -->
	<script type="application/javascript"><?php echo $jscode; ?></script>
	<!-- Not whitelisted inline script: -->
	<script type="application/javascript">
alert('This should not popup.'); 
	</script>
	</body>
</html>
