<?php
require_once('../CSPGenerator.php');

// Add a style-src nonce.
CSPGenerator::getInstance()->setStylesrcNonce();


// Set the headers, always call this method before any content output.
CSPGenerator::getInstance()->Parse();
// Start content output.
?><!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>example5</title>
        <!-- Because of valid nonce the following css should be applied. -->
        <style type="text/css" nonce="<?php echo CSPGenerator::getInstance()->getStylesrcNonce(); ?>">
.hidetext {
    visibility: hidden;
}
.bigtext {
    font-size: 16pt;
}
        </style>
        <!-- Because of invalid nonce the following css should not be applied. -->
        <style type="text/css" nonce="deliberately_invalid_nonce">
.hidetext {
    visibility: visible !important;
    color: #FF2121;
    font-size: 16pt;
}
        </style>
    </head>
    <body>
        <span class="hidetext">not</span>
        <span class="bigtext">working</span>
    </body>
</html>