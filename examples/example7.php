<?php
require_once('../CSPGenerator.php');

// Start content output.
?><!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>example7 - CSP in meta tag</title>
		<?php echo CSPGenerator::getInstance()->getMetatagContentSecurityPolicy(); ?>
	</head>
	<body>
	The Content Security Policy in the META tag can cannot use frame-ancestors, report-uri,<br />
	or sandbox directives and has currently limited browser support. The META tag CSP<br />
	provides weaker security because an injection before the META tag can still change things.<br />
	</body>
</html>
