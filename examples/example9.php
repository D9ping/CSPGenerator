<?php
require_once('../CSPGenerator.php');

CSPGenerator::getInstance()->addScriptsrc('https://cdn.jsdelivr.net');
// Set that all scripts need integrity attribute. 
CSPGenerator::getInstance()->addRequireSRIfor('script');

// Set the headers, always call this method before any content output.
CSPGenerator::getInstance()->Parse();
// Start content output.
?><!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>example9 - require-sri-for</title>
	</head>
	<body>
		Open console(F12) and verify that jQuery javascript library is loaded.<br />

		<script type="application/javascript" src="https://cdn.jsdelivr.net/npm/jquery@3.3.1/dist/jquery.min.js"
 integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8="></script>
 
		But qunit javascript library could be blocked on modern webbrowsers due to missing integrity attribute.<br />
		<small>(Firefox 49-60 requires in about:config to set security.csp.experimentalEnabled to true.)</small><br />

		<script type="application/javascript" src="https://cdn.jsdelivr.net/npm/qunit@2.6.1/qunit/qunit.js"></script>

	</body>
</html>
