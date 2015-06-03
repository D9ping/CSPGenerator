<?php
require_once('../CSPGenerator.php');

// Allow use of some inline JavaScript by the use of nonces.
CSPGenerator::getInstance()->setScriptsrcNonce();


// Set the headers, always call this method before any content output.
CSPGenerator::getInstance()->Parse();
// Start content output.
?><!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>example4</title>
    </head>
    <body>
        <div id="result">..  <noscript>javascript not enabled!</noscript></div>

        <script type="application/javascript" nonce="<?php echo CSPGenerator::getInstance()->getScriptsrcNonce(); ?>">
document.getElementById('result').textContent = 'okay, whitelisted inline script loaded.';
        </script>

        <script type="application/javascript" nonce="deliberately_invalid_nonce_here">
document.getElementById('result').textContent = 'bad, inline script with invalid nonce is not blocked.';
        </script>

        <script type="application/javascript">
document.getElementById('result').textContent = 'bad, inline script without a nonce is not blocked.';
        </script>
    </body>
</html>
