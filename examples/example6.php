<?php
require_once('../CSPGenerator.php');

// E.g. allow inline google analytics javascript snippet.
// The following javascript code needs hashed before the Content Security Policy
// HTTP header is send to the client.
$jscode = "
window['ga-disable-UA-XXXXX-Y'] = true;
(function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
(i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
})(window,document,'script','https://www.google-analytics.com/analytics.js','ga');
ga('create', 'UA-XXXXX-Y', 'auto');
ga('set', 'anonymizeIp', true);
ga('send', 'pageview');

  alert('The (disabled)Google analytics snippet loaded.');
";

CSPGenerator::getInstance()->addScriptsrcHash($jscode, 'sha384');
CSPGenerator::getInstance()->addScriptsrc('https://www.google-analytics.com');
CSPGenerator::getInstance()->addImagesrc('https://www.google-analytics.com');

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
	See page sourcecode.
	</body>
</html>
