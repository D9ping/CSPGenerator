<?php 
/*
Copyright (c) 2014-2018, Tom
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted 
provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of 
   conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
   the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse
   or promote products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF 
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
 * Content Security Policy generator.
 */
class CSPGenerator {

    private static $instance;

    private $reportonly = false;

    private $upgradeinsecurerequests = false;

    private $blockmixedcontent = false;

    private $defaultsrc = " 'none'";

    private $stylesrc = " 'self'";

    private $stylesrcnonce = '';

    private $imagesrc = " 'self'";

    private $scriptsrc = " 'self'";

    private $scriptsrcnonce = '';

    private $connectsrc = '';

    private $mediasrc = '';

    private $manifestsrc = '';

    private $fontsrc = '';

    private $framesrc = '';

    private $workersrc = '';

    private $childsrc = '';

    private $frameancestors = '';

    private $objectsrc = '';

    private $plugintypes = '';

    private $formaction = " 'self'";

    private $sandboxoptions = '';

    private $referrerpolicy = '';

    private $requiredsrifqdns = '';

    private $reflectedxss = 'filter';

    private $baseuri = '';

    private $reportto = '';

    const NONCEMINLENGTH = 10;

    /**
     * Create a new instance of CSPGenerator class.
     */
    private function __construct()
    {
    }

    /**
     * Get instance of CSPGenerator class.
     */
    public static function getInstance()
    {
        if (empty(self::$instance)) {
            self::$instance = new CSPGenerator();
        }

        return self::$instance;
    }

    /**
     * Set the url to where to report violations of the Content Security Policy.
     * Will also set the decreated report-uri Content Security Policy directive.
     *
     * @param $string $reportto The url to report the Content Security Policy violation reports on.
     */
    public function setReportTo($reportto)
    {
        if (!$this->isValidDirectiveValue($reportto)) {
            throw new InvalidArgumentException('reportto invalid.');
        }

        $this->reportto = $reportto;
    }

    public function setReporturi($reporturidecreated)
    {
        error_log('Called decreated setReporturi function. Replace this with setReportTo.');
        $this->setReportTo($reporturidecreated);
    }

    /**
     * Set report only mode.
     */
    public function setReportOnly()
    {
        $this->reportonly = true;
    }

    /**
     * Parse user-agent header and set proper Content Security Policy header,
     * X-Frame-Options header and X-XSS-Protection header based on the browser and browser version.
     */
    public function Parse()
    {
        $useragentinfo = $this->getBrowserInfo();
        //header('X-DebugDetectBrowser: '.$useragentinfo['browser']);
        $cspheader = $this->getUseragentContentSecurityPolicy($useragentinfo);
        header($cspheader, true);
        // Add X-Frame-Options header based on the content security policy frame-ancestors directive.
        if (strpos($this->frameancestors, "'none'") >= 0 ||
            empty($this->frameancestors) && strpos($this->defaultsrc, "'none'") >= 0) {
            header('X-Frame-Options: DENY', true);
        } elseif (strpos($this->frameancestors, "'self'") >= 0 || empty($this->frameancestors)) {
            header('X-Frame-Options: SAMEORIGIN', true);
        } elseif (strpos($this->frameancestors, ' *') >= 0) {
            header('X-Frame-Options: ALLOW', true);
        } else {
            // ALLOW-FROM Not supported in Chrome or Safari or Opera and any Firefox less than version 18.0 and any Internet Explorer browser less than version 9.0. (source: http://erlend.oftedal.no/blog/tools/xframeoptions/)
            if (($useragentinfo['browser'] === 'firefox' && $useragentinfo['version'] >= 18) || 
                ($useragentinfo['browser'] === 'msie' && $useragentinfo['version'] >= 9)) {
                header('X-Frame-Options: ALLOW-FROM '.$this->frameancestors, true);
            }
        }

        if (!empty($this->referrerpolicy)) {
            if ($useragentinfo['browser'] === 'firefox' && $useragentinfo['version'] >= 50) {
                header('Referrer-Policy: '.$this->referrerpolicy, true);
            }
        }

        // Add X-XSS-Protection header based on CSP 1.1 settings.
        switch ($this->reflectedxss) {
            case 'filter':
                // filter is the prefered one, because mode=block can cause possible insecurity, source: http://homakov.blogspot.nl/2013/02/hacking-with-xss-auditor.html
                header('X-XSS-Protection: 1', true);
                break;
            case 'allow':
                header('X-XSS-Protection: 0', true);
                break;
            case 'block':
                header('X-XSS-Protection: 1; mode=block', true);
                break;
        }
    }

    /**
     * Get the (X)HTML META tag for defining the Content Security Policy.
     * frame-ancestors, report-uri, or sandbox directive will not work in the META tag.
     * Because several directives cannot work in META tag it's recommended to use
     * HTTP header instead if possible.
     */
    public function getMetatagContentSecurityPolicy()
    {
        $cspheader = $this->getUseragentContentSecurityPolicy($this->getBrowserInfo());
        $csp = explode(': ', $cspheader, 2);
        $cspmetatag = '<meta http-equiv="';
        $cspmetatag .= $csp[0];
        $cspmetatag .= '" content="';
        $cspmetatag .= $csp[1];
        $cspmetatag .= '" />'."\r\n";
        return $cspmetatag;
    }

    /**
     * Get the Content Security Policy that is supported/compatible with the current user-agent.
     */
    private function getUseragentContentSecurityPolicy($useragentinfo)
    {
        $cspheader = 'Content-Security-Policy: ';
        if ($useragentinfo['browser'] === 'chrome') {
            // Whitelist google translate, because it's commonly enabled and used by chrome webbrowsers:
            $this->addConnectsrc('https://translate.googleapis.com');
            // unsafe-inline is needed for google translate to display the content:
            $this->addStylesrc("'unsafe-inline'");
            // You can also comment out the above lines and add: <meta name="google" content="notranslate" />
        }

        if ($this->reportonly) {
            $cspheader = 'Content-Security-Policy-Report-Only: ';
        }

        if ($useragentinfo['browser'] === 'firefox' && $useragentinfo['version'] <= 22 && $useragentinfo['version'] >= 3.7) {
            if ($this->reportonly) {
                $cspheader = 'X-Content-Security-Policy-Report-Only: ';
            } else {
                $cspheader = 'X-Content-Security-Policy: ';
            }

            // X-Content-Security-Policy: uses allow instead of default-src.
            $cspheader .= 'allow '.$this->defaultsrc;
        } elseif ( ($useragentinfo['browser'] === 'chrome' && $useragentinfo['version'] <= 24 && $useragentinfo['version'] >= 14) || 
                   ($useragentinfo['browser'] === 'safari' && $useragentinfo['version'] >= 6 && $useragentinfo['version'] < 7) ) {
            // Safari 5.0/5.1 X-WebKit-CSP implementation is badly broken it blocks permited\whitelisted things so it's not usable at all.
            if ($this->reportonly) {
                $cspheader = 'X-WebKit-CSP-Report-Only: ';
            } else {
                $cspheader = 'X-WebKit-CSP: ';
            }

            $cspheader .= 'default-src'.$this->defaultsrc;
        } else {
            $cspheader .= 'default-src'.$this->defaultsrc;
        }

        if (!empty($this->stylesrc)) {
            // The obsolete decreated X-Content-Security-Policy header does not support style-src. This is not implemented.
            $cspheader .= '; style-src'.$this->stylesrc;
            if (!empty($this->stylesrcnonce)) {
                $cspheader .= " 'nonce-".$this->stylesrcnonce."'";
            }
        }

        if (!empty($this->imagesrc)) {
            $cspheader .= '; img-src'.$this->imagesrc;
        }

        if (!empty($this->scriptsrc)) {
            $cspheader .= '; script-src'.$this->scriptsrc;
            if (!empty($this->scriptsrcnonce)) {
                $cspheader .= " 'nonce-".$this->scriptsrcnonce."'";
            }

            // for inline script with the X-Content-Security-Policy header use 'options inline-script'.
            if ($useragentinfo['browser'] === 'firefox' &&
                $useragentinfo['version'] <= 22 &&
                $useragentinfo['version'] >= 3.7) {
                if (strpos($this->scriptsrc, "'unsafe-inline'") >= 0) {
                    $cspheader .= '; options inline-script';
                }
            }
        }

        // Chrome for iOS fails to render page if "connect-src 'self'" is missing.
        if ($useragentinfo['browser'] === 'chrome') {
            $this->addConnectsrc("'self'");
        }

        if (!empty($this->connectsrc)) {
            // The decreated X-Content-Security-Policy header uses xhr-src instead of connect-src.
            if ($useragentinfo['browser'] === 'firefox' && $useragentinfo['version'] <= 22 && $useragentinfo['version'] >= 3.7) {
                $cspheader .= '; xhr-src'.$this->connectsrc;
            } else {
                $cspheader .= '; connect-src'.$this->connectsrc;
            }
        }

        if (!empty($this->mediasrc)) {
            // TODO Lookup what version Chrome added support for media-src.
            if ($useragentinfo['browser'] !== 'firefox' || $useragentinfo['version'] >= 23) {
                // CSP 1.0
                $cspheader .= '; media-src'.$this->mediasrc;
            }
        }

        if (!empty($this->fontsrc)) {
            // TODO Lookup what version Chrome added support for font-src.
            // CSP 1.0
            $cspheader .= '; font-src'.$this->fontsrc;
        }

        if (empty($this->workersrc) && empty($this->framesrc)) {
            if (!empty($this->childsrc)) {
                // Decreated, only CSP Level 2:
                if ($useragentinfo['browser'] == 'chrome' || $useragentinfo['version'] >= 45) {
                    $cspheader .= '; child-src'.$this->childsrc;
                }
            }
        } else {
            if (!empty($this->framesrc)) {
                // CSP 1.0,
                if ($useragentinfo['version'] < 100) {
                    $cspheader .= '; frame-src'.$this->framesrc;
                }
            }

            if (!empty($this->workersrc)) {
                // CSP 3
                $cspheader .= '; worker-src'.$this->workersrc;
            }
        }

        if (!empty($this->frameancestors)) {
            // CSP 1.1
            $cspheader .= '; frame-ancestors'.$this->frameancestors;
        }

        if (!empty($this->objectsrc)) {
            // CSP 1.0
            $cspheader .= '; object-src'.$this->objectsrc;
        }

        // Experimental:
        if (!empty($this->plugintypes)) {
            if ($useragentinfo['browser'] === 'opr' && $useragentinfo['version'] >= 27 ||
                $useragentinfo['browser'] === 'chrome' && $useragentinfo['version'] >= 40) {
                $cspheader .= '; plugin-types'.$this->plugintypes;
            }
        }

        // Experimental:
        if (!empty($this->manifestsrc)) {
            if ($useragentinfo['browser'] === 'firefox' && $useragentinfo['version'] >= 41 ||
                $useragentinfo['browser'] === 'chrome' && $useragentinfo['version'] >= 45) {
                $cspheader .= '; manifest-src'.$this->manifestsrc;
            }
        }

        // Experimental:
        if (!empty($this->referrerpolicy)) {
            if ($useragentinfo['browser'] === 'firefox' && $useragentinfo['version'] >= 37 ||
                $useragentinfo['browser'] === 'chrome' && $useragentinfo['version'] >= 45) {
                $cspheader .= '; referrer '.$this->referrerpolicy;
            }
        }

        // Experimental:
        if (!empty($this->formaction)) {
            if ($useragentinfo['browser'] === 'firefox' && $useragentinfo['version'] >= 36 ||
                $useragentinfo['browser'] === 'opr' && $useragentinfo['version'] >= 27 ||
                $useragentinfo['browser'] === 'chrome' && $useragentinfo['version'] >= 40) {
                $cspheader .= '; form-action'.$this->formaction;
           }
        }

        // Experimental:
        if (!empty($this->reflectedxss)) {
            if ($useragentinfo['browser'] === 'chrome' && $useragentinfo['version'] >= 60) {
                // Not implemented in Chromium 56.0.2915
                $cspheader .= '; reflected-xss '.$this->reflectedxss;
            }
        }

        // Experimental:
        if (!empty($this->baseuri)) {
            if ($useragentinfo['browser'] === 'firefox' && $useragentinfo['version'] >= 35 ||
                $useragentinfo['browser'] === 'chrome' && $useragentinfo['version'] >= 40) {
                $cspheader .= '; base-uri'.$this->baseuri;
            }
        }

        // Experimental:
        if ($this->upgradeinsecurerequests) {
            if ($useragentinfo['browser'] === 'chrome' && $useragentinfo['version'] >= 43 ||
                $useragentinfo['browser'] === 'firefox' && $useragentinfo['version'] >= 42 ||
                $useragentinfo['browser'] === 'opr' && $useragentinfo['version'] >= 30) {
                // Not supported on Edge and Safari.
                $cspheader .= '; upgrade-insecure-requests';
            }
        }

        if ($this->blockmixedcontent) {
            if ($useragentinfo['browser'] === 'chrome' && $useragentinfo['version'] >= 56) {
                // Worked on Chromium 56.0.2915
                $cspheader .= '; block-all-mixed-content';
            }
        }

        if (!empty($this->reportto)) {
            $cspheader .= '; report-uri '.$this->reportto;
            $cspheader .= '; report-to '.$this->reportto;
        }

        return $cspheader;
    }

    /**
     * Get browser name and version from the user-agent header.
     *
     * @return string[]
     */
    private function getBrowserInfo()
    {
        // Declare known browsers to look for
        $browsers = array('chrome', 'firefox', 'edge', 'msie', 'safari', 'opr', 'opera');

        // Clean up useragent and build regex that matches phrases for known browsers
        // (e.g. "Firefox/2.0" or "MSIE 6.0" (This only matches the major and minor
        // version numbers.  E.g. 2.0.0.6 is parsed as simply 2.0.
        if (!isset($_SERVER['HTTP_USER_AGENT'])) {
            return array('browser' => 'unknown', 'version' => -1.0);
        }

        $useragent = strtolower($_SERVER['HTTP_USER_AGENT']);
        $pattern = '#(?<browser>'.join('|', $browsers) .')[/ ]+(?<version>[0-9]+(?:\.[0-9]+)?)#';
        // Find all phrases (or return empty array if none found)
        if (!preg_match_all($pattern, $useragent, $matches)) {
            if (strpos($useragent, 'Trident/') >= 0) {
                // IE 11 does not have msie in user-agent header anymore, IE developers want forcing
                // feature detecting with javascript. This is not for HTTP headers possible, 
                // because then the headers are already send. 
                // source: http://blogs.msdn.com/b/ieinternals/archive/2013/09/21/internet-explorer-11-user-agent-string-ua-string-sniffing-compatibility-with-gecko-webkit.aspx
                return array('browser' => 'msie', 'version' => 11);
            } else {
                // Unknown browser.
                return array('browser' => 'unknown', 'version' => -1.0);
            }
        }

        // Since some UAs have more than one phrase (e.g Firefox has a Gecko phrase, Opera 7,8 have a MSIE phrase), 
        // use the last one found (the right-most one in the UA). That's usually the most correct.
        $i = count($matches['browser']) - 1;
        $secondlast = 0;
        if ($i >= 2) {
            $secondlast = $i - 1;
        }

        if ($matches['version'][$i] === '537.36' && $matches['browser'][$i] === 'safari') {
            return array('browser' => $matches['browser'][$secondlast], 'version' => $matches['version'][$secondlast]);
        } else {
            return array('browser' => $matches['browser'][$i], 'version' => $matches['version'][$i]);
        }
    }

    /**
     * Set the default-src content security policy directive. Don't allow an empty default policy.
     *
     * @param string $defaultsrc The default-src policy directive. Style-src, image-src, 
     *                           script-src, frame-src, connect-src, font-src, objectsrc
     *                           and media-src all inherit from this.
     */
    public function setDefaultsrc($defaultsrc)
    {
        if (!$this->isValidDirectiveValue($defaultsrc)) {
            throw new InvalidArgumentException('defaultsrc value invalid');
        }

        if (empty($defaultsrc)) {
            throw new InvalidArgumentException('CSP default-src policy directive cannot be empty.');
        }

        $this->defaultsrc = $defaultsrc;
    }

    /**
     * Add style-src Content Security Policy 1.0 directive.
     * In Content Security Policy Level 1.1 and Level 2, the use of 'none-$nonce' and 'sha256-$hash'
     * is allowed for whitelisted inline style= use.
     *
     * @param string $stylesrc The style-src policy directive to add. Where to allow CSS
     *                         files from use 'unsafe-inline' for style attributes in (X)HTML document.
     */
    public function addStylesrc($stylesrc)
    {
        if (!$this->isValidDirectiveValue($stylesrc)) {
            throw new InvalidArgumentException('stylesrc value invalid');
        }

        if (strpos($this->stylesrc, $stylesrc) === false) {
            $this->stylesrc .= ' '.$stylesrc;
        }
    }

    /**
     * Add image-src Content Security Policy 1.0 directive.
     *
     * @param string $imagesrc The image-src policy directive to add. Where to allow images from. 
     *                         Use data: for base64 data url images.
     */
    public function addImagesrc($imagesrc)
    {
        if (!$this->isValidDirectiveValue($imagesrc)) {
            throw new InvalidArgumentException('imagesrc value invalid');
        }

        if (strpos($this->imagesrc, $imagesrc) === false) {
            $this->imagesrc .= ' '.$imagesrc;
        }
    }

    /**
     * Add script-src Content Security Policy 1.0 directive.
     * In Content Security Policy 1.1 and Level 2, the use of 'none-$nonce' and 'sha256-$hash' is allowed for whitelisted inline scripts.
     * 'unsafe-inline' can be ignored by user-agent because it's so unsafe.
     * The following Content Security Policy Level 3 special directives are allowed:
     * 'strict-dynamic' will allow scripts to load their dependencies without them having to be whitelisted.
     * 'unsafe-hashed-attributes'  will allow event handlers to whitelisted based on their hash.
     *
     * @param string $scriptsrc The script-src policy directive to add. Use 'unsafe-inline' to allow unsafe loading of iniline scripts, use 'unsafe-eval' to allow text-to-JavaScript mechanisms like eval.
     */
    public function addScriptsrc($scriptsrc)
    {
        if (!$this->isValidDirectiveValue($scriptsrc)) {
            throw new InvalidArgumentException('scriptsrc value invalid');
        }

        if (strpos($this->scriptsrc, $scriptsrc) === false) {
            $this->scriptsrc .= ' '.$scriptsrc;
        }
    }

    /**
     * Add a new script-src hashcode for a script.
     *
     * @param string $sourcecode The exact sourcecode of the script to allow inline to be included in the page. 
     *                           Don't forget linefeed(\n) and carriage return(\r) characters.
     * @param string $hashalgo   The hashing algorithm to use, can be "sha256"(default), "sha384" or "sha512".
     *                           SHA(2)-384 and SHA(2)-512 are optimized for 64bits processors+software.
     */
    public function addScriptsrcHash($sourcecode, $hashalgo = 'sha256')
    {
        $this->addScriptsrc($this->generateSourceHash($sourcecode, $hashalgo));
    }

    /**
     * Set a new script nonce.
     *
     * @param bool $enablenonce Is the use of a nonces enabled for allowing inline scripts. 
     *                          Set to true to add a random 'nonce-$random' to script-src directive
     *                          and set to false to remove 'nonce-$random' from the script-src directive.
     * @param int  $noncelength The length of the new nonce. It's recommended to use (at least)128 bits nonces.
      *                         With the use of all ASCII printable characters you get about 6.570 bits entropy per character.
     */
    public function setScriptsrcNonce($enablenonce = true, $noncelength = 20)
    {
        if ($enablenonce) {
            $this->scriptsrcnonce = $this->generateNonce($noncelength);
        } else {
            $this->scriptsrcnonce = '';
        }
    }

    /**
     * Add a new style-src hash code.
     *
     * @param string $sourcecode The exact content of style tag.
     * @param string $hashalgo   The hashing algorithm to use, can be "sha256"(default), "sha384" or "sha512".
     *                           SHA(2)-384 and SHA(2)-512 are optimized for 64bits processors+software.
     */
    public function addStylesrcHash($sourcecode, $hashalgo = 'sha256')
    {
        $this->addStylesrc($this->generateSourceHash($sourcecode, $hashalgo));
    }

    /**
     * Set a new style nonce.
     *
     * @param bool $enablenonce Is the use of a nonces enabled for allowing inline styles. 
     *                          Set to true to add a random 'nonce-$random' to style-src directive
     *                          and set to false to remove 'nonce-$random' from the style-src directive.
     * @param int  $noncelength The length of the new nonce. It's recommended to use (at least)128 bits nonces.
     *                          With the use of all ASCII printable characters you get
     *                          about 6.570 bits entropy per character.
     */
    public function setStylesrcNonce($enablenonce = true, $noncelength = 20)
    {
        if ($enablenonce) {
            $this->stylesrcnonce = $this->generateNonce($noncelength);
        } else {
            $this->stylesrcnonce = '';
        }
    }

    /**
     * Generate a new hash code for the $sourcecode value
     *
     * @param string $sourcecode The content to generate the hash from. \r characters are removed.
     * @param string $hashalgo   The hashing algorithm to use, can be "sha256"(default), "sha384" or "sha512".
     * @return string A new hash code as base64 with $hashalgo- prefix and wrapped around single quotes.
     */
    private function generateSourceHash($sourcecode, $hashalgo)
    {
        if (!isset($sourcecode)) {
            throw new InvalidArgumentException('Sourcecode is missing.');
        }

        if ($hashalgo !== 'sha256' && $hashalgo !== 'sha384' && $hashalgo !== 'sha512') {
            throw new InvalidArgumentException(sprintf('Hashing algorithm %1$s not supported.', $hashalgo));
        }

        $sourcecode = str_replace("\r", '', $sourcecode); // remove \r to make it work.
        $sourcehashbase64 = base64_encode(hash($hashalgo, $sourcecode, true));
        return "'".$hashalgo."-".$sourcehashbase64."'";
    }

    /**
     * Generate a new nonce with certain length.
     *
     * @param int $noncelength The length of the nonce to generate.
     * @return string A new nonce.
     */
    private function generateNonce($noncelength)
    {
        if ($noncelength < self::NONCEMINLENGTH) {
            throw new InvalidArgumentException(sprintf('The nonce length needs to be at least %1$d characters.', self::NONCEMINLENGTH));
        }

        if (function_exists('random_bytes')) { // random_bytes is added in PHP 7.0. An userland implementation could be available for lower php versions.
            return substr(base64_encode(random_bytes($noncelength)), 0, $noncelength);
        } elseif (function_exists('mcrypt_create_iv')) {
            return substr(base64_encode(mcrypt_create_iv($noncelength, MCRYPT_DEV_URANDOM)), 0, $noncelength);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            return substr(base64_encode(openssl_random_pseudo_bytes($noncelength)), 0, $noncelength);
        } else {
            throw new Exception('No secure pseudo random generator available for generating nonce.');
        }
    }

    /**
     * Get the current script-src nonce.
     *
     * @return string The nonce string.
     */
    public function getScriptsrcNonce()
    {
        if (empty($this->scriptsrcnonce)) {
            throw new InvalidArgumentException('No script-src nonce used.');
        }

        return $this->scriptsrcnonce;
    }

    /**
     * Get the current style-src nonce.
     *
     * @return string The nonce string.
     */
    public function getStylesrcNonce()
    {
        if (empty($this->stylesrcnonce)) {
            throw new InvalidArgumentException('No style-src nonce used.');
        }

        return $this->stylesrcnonce;
    }

    /**
     * Add connect-src Content Security Policy 1.0 directive.
     * Status: Candidate Recommendation.
     *
     * @param string $connectsrc The connect-src policy directive to add. Where to allow XMLHttpRequest to connect to.
     */
    public function addConnectsrc($connectsrc)
    {
        if (!$this->isValidDirectiveValue($connectsrc)) {
            throw new InvalidArgumentException('connectsrc value invalid');
        }

        if (strpos($this->connectsrc, $connectsrc) === false) {
            $this->connectsrc .= ' '.$connectsrc;
        }
    }

    /**
     * Add media-src Content Security Policy 1.0 directive.
     * Status: Candidate Recommendation.
     *
     * @param string $mediasrc The media-src policy directive to add. Where to allow to load video/audio sources from. Use mediastream: for the MediaStream API. 
     */
    public function addMediasrc($mediasrc)
    {
        if (!$this->isValidDirectiveValue($mediasrc)) {
            throw new InvalidArgumentException('mediasrc value invalid');
        }

        if (strpos($this->mediasrc, $mediasrc) === false) {
            $this->mediasrc .= ' '.$mediasrc;
        }
    }

    /**
     * Add manifest-src Security Policy Level 2 directive.
     * Status: Candidate Recommendation.
     */
    public function addManifestsrc($manifestsrc)
    {
        if (!$this->isValidDirectiveValue($manifestsrc)) {
            throw new InvalidArgumentException('manifestsrc value invalid');
        }

        if (strpos($this->manifestsrc, $manifestsrc) === false) {
            $this->manifestsrc .= ' '.$manifestsrc;
        }
    }

    /**
     * Add font-src Content Security Policy 1.0 directive.
     * Status: Candidate Recommendation.
     *
     * @param string $fontsrc The font-src policy directive to add. Where to allow to load font files from.
     */
    public function addFontsrc($fontsrc)
    {
        if (!$this->isValidDirectiveValue($fontsrc)) {
            throw new InvalidArgumentException('fontsrc value invalid');
        }

        if (strpos($this->fontsrc, $fontsrc) === false) {
            $this->fontsrc .= ' '.$fontsrc;
        }
    }

    /**
     * Add frame-src Content Security Policy 1.0 directive.
     * Warning: frame-src is decreated in Content Security Policy Level 2 in favor of the child-src directive.
     *
     * @param string $framesrc The frame-src policy directive to add. Where to allow to load frames/iframe from.
     */
    public function addFramesrc($framesrc)
    {
        if (!$this->isValidDirectiveValue($framesrc)) {
            throw new InvalidArgumentException('framesrc value invalid');
        }

        if (strpos($this->framesrc, $framesrc) === false) {
            $this->framesrc .= ' '.$framesrc;
        }
    }

    /**
     * Added allowed web worker sources.
     *
     * @param string $workersrc 
     */
    public function addWorkersrc($workersrc)
    {
        if (!$this->isValidDirectiveValue($workersrc)) {
            throw new InvalidArgumentException('workersrc value invalid');
        }

        if (strpos($this->workersrc, $workersrc) === false) {
            $this->workersrc .= ' '.$workersrc;
        }
    }

    /**
     * Add the child-src Content Security Policy Level 2 directive.
     * This directive also applies to the decreated frame-src directive.
     * Status: decreated.
     *
     * @param string $childsrc The child-src policy directive to add. Where webworkers and
     *                         frames/iframe are allowed to load from.
     */
    public function addChildsrc($childsrc)
    {
        error_log('Decreated child-src used, replace calls to addChildsrc with: addFramesrc or addWorkersrc.');
        if (!$this->isValidDirectiveValue($childsrc)) {
            throw new InvalidArgumentException('childsrc value invalid');
        }

        if (strpos($this->childsrc, $childsrc) === false) {
            $this->childsrc .= ' '.$childsrc;
        }
    }

    /**
     * Add the frame-ancestors Content Security Policy Level 2 directive.
     * This directive does the same as the X-Frame-Options header.
     * Status: Candidate Recommendation.
     *
     * @param string $frameancestors The frame-ancestors policy directive to add.
     *                               'self' is the same as X-Frame-Options: SAMEORIGIN,
     *                               'none' is the same as X-Frame-Options: DENY,
     *                                   *  is the same as X-Frame-Options: ALLOW
     */
    public function addFrameancestors($frameancestors)
    {
        if (!$this->isValidDirectiveValue($frameancestors)) {
            throw new InvalidArgumentException('frameancestors value invalid');
        }

        if ($frameancestors === 'DENY') {
            throw new InvalidArgumentException("Use 'none' instead of DENY.");
        } elseif ($frameancestors === 'SAMEORIGIN') {
            throw new InvalidArgumentException("Use 'self' instead of SAMEORIGIN.");
        } elseif ($frameancestors === 'ALLOW') {
            throw new InvalidArgumentException("Use * instead of ALLOW.");
        }

        if (strpos($this->frameancestors, $frameancestors) === false) {
            $this->frameancestors .= ' '.$frameancestors;
        }
    }

    /**
     * Add the object-src Content Security Policy 1.0 directive.
     * Status: Candidate Recommendation.
     *
     * @param string $objectsrc The object-src policy directive to add. Where to allow to 
     *                          load plugins objects like flash/java applets from.
     */
    public function addObjectsrc($objectsrc)
    {
        if (!$this->isValidDirectiveValue($objectsrc)) {
            throw new InvalidArgumentException('objectsrc value invalid');
        }

        if (strpos($this->objectsrc, $objectsrc) === false) {
            $this->objectsrc .= ' '.$objectsrc;
        }
    }

    /**
     * Add the plugin-types Content Security Policy Level 2 directive.
     * Status: Candidate Recommendation.
     *
     * @param string $plugintypes The plugin-types policy directive to add. A list of MIME types
     *         (e.g. application/x-shockwave-flash, application/pdf) of plugins allowed to load.
     */
    public function addPlugintypes($plugintypes)
    {
        if (!$this->isValidDirectiveValue($plugintypes)) {
            throw new InvalidArgumentException('plugintypes value invalid');
        }

        if (strpos($this->plugintypes, $plugintypes) === false) {
            $this->plugintypes .= ' '.$plugintypes;
        }
    }

    /**
     * Add the form-action Content Security Policy Level 2 directive.
     * Status: Candidate Recommendation.
     *
     * @param string $formaction The form-action policy directive to add. Restricts which 
     *                           URI's can be used as the action of HTML form elements.
     */
    public function addFormaction($formaction)
    {
        if (!$this->isValidDirectiveValue($formaction)) {
            throw new InvalidArgumentException('formaction value invalid');
        }

        if (strpos($this->formaction, $formaction) === false) {
            $this->formaction .= ' '.$formaction;
        }
    }

    /**
     * Add the base-uri Content Security Policy Level 2 directive.
     * This directive is by default not restricted by the default-src directive.
     * Status: Candidate Recommendation.
     *
     * @param string $baseuri The base-uri policy directive to add.  Defines the URIs that 
     *                        a user agent may use as the document base URL.
     */
    public function addBaseuri($baseuri)
    {
        if (strpos($this->baseuri, $baseuri) === false) {
            $this->baseuri .= ' '.$baseuri;
        }
    }

    /**
     * Add sandbox options to the sandbox Content Security Policy 1.0 directive.
     * Status: Candidate Recommendation.
     *
     * @param string $sandboxoption The sandbox policy directive to add. This can be: allow-forms, allow-pointer-lock, allow-popups, allow-same-origin, allow-scripts or allow-top-navigation.
     */
    public function addSandboxoption($sandboxoption)
    {
        $sandboxoption = strtolower($sandboxoption);
        if ($sandboxoption === 'allow-forms' ||
            $sandboxoption === 'allow-pointer-lock' ||
            $sandboxoption === 'allow-popups' ||
            $sandboxoption === 'allow-same-origin' ||
            $sandboxoption === 'allow-scripts' ||
            $sandboxoption === 'allow-top-navigation') {
            if (strpos($this->sandboxoptions, $sandboxoption) === false) {
                $this->sandboxoptions .= ' '.$sandboxoption;
            }
        } else {
            throw new InvalidArgumentException('CSP sandbox option unknown.');
        }
    }

    /**
     * Set the referrer policy. This directive will change the behavoir how the user-agent sends the referrer(Mispelled HTTP header field: referer).
     * Status: Working Draft.
     *
     * @param string $referrerpolicy The referrer policy can be one of these values:
     *                               "no-referrer"(obsolete policy name: "never"), do not send any http referrer header at all. Most privacy friendly, but not good choice as weak protection if implemented against CSRF.
     *                               "no-referrer-when-downgrade"(obsolete policy name: "default"), default bevavior when no policy. Will send the full referrer but do not send referrer header when coming from https to protect you from dislosing your session url.
     *                               "origin" only send the domain(e.g. www.example.tld) and not the uri(e.g. /page2.htm). A bit more privacy friendly than the full referrer but not when going from https to http.
     *                               "strict-origin" send the domain(e.g. www.exmaple.tld) and also for navigating to subdomain(e.g. not.example.tld). But never send and the uri(the page).
     *                               "origin-when-cross-origin" Only send origin when going to a different origin but not when going from https to http.
     *                               "strict-origin-when-cross-origin" Send origin when going to a different origin and send only origin when going to subdomain. Do send full url when navigating on same origin. But do not send any referrer when going from https to http on any origin.
     *                               "unsafe-url"(obsolete policy name: "always"). Will always send the full referrer. This will also send the full referrer on HTTP when coming from a HTTPS site and that can be a security(session urls) and privacy issue.
     */
    public function setReferrerPolicy($referrerpolicy)
    {
        switch (strtolower($referrerpolicy)) {
            case 'default':
            case 'no-referrer-when-downgrade':
                $this->referrerpolicy = 'no-referrer-when-downgrade';
                break;
            case 'never':
            case 'no-referrer':
                $this->referrerpolicy = 'no-referrer';
                break;
            case 'same-origin':
                $this->referrerpolicy = 'same-origin';
                break;
            case 'origin-when-cross-origin':
                $this->referrerpolicy = 'origin-when-cross-origin';
                break;
            case 'strict-origin-when-cross-origin':
                $this->referrerpolicy = 'strict-origin-when-cross-origin';
                break;
            case 'origin':
                $this->referrerpolicy = 'origin';
                break;
            case 'strict-origin':
                $this->referrerpolicy = 'strict-origin';
                break;
            case 'always':
            case 'unsafe-url':
                $this->referrerpolicy = 'unsafe-url';
                break;
            default:
                throw new InvalidArgumentException('Referrer policy value unknown.');
                break;
        }
    }

    /**
     * Set reflected-xss Policy Content Security Policy Level 2 directive.
     * Status: Candidate Recommendation.
     *
     * @param string $reflectedxss The reflected-xss policy. This can be:
     *                             "allow" no url filtering, does the same as X-XSS-Protection: 0;
     *                             "filter" filter detected unsafe url and display warning bar(with unsafe reload option) does the same as X-XSS-Protection: 1;
     *                             "block" block with about:blank. Does the same as  X-XSS-Protection: 1; mode=block;
     */
    public function setReflectedxss($reflectedxss)
    {
        $reflectedxss = strtolower($reflectedxss);
        if ($reflectedxss === 'filter' || $reflectedxss === 'block' || $reflectedxss === 'allow') {
            $this->reflectedxss = $reflectedxss;
        } else {
            throw new InvalidArgumentException('CSP reflectedxss directive value unknown.');
        }
    }

    /**
     * Set a fully qualified domain names to require Subresource Integrity(SRI) for 
     * with this Content Security Policy Level 3 directive.
     * Status: Working Draft.
     * 
     * @param string $fqdn A fully qualified domain name.
     */
    public function setRequireSRIfor($fqdn)
    {
        if (empty($fqdn)) {
            throw new InvalidArgumentException('No fully qualified domain name value provided.');
        } elseif (!$this->isValidFQDN($fqdn)) {
            throw new InvalidArgumentException('Given value cannot be a valid fully qualified domain name.');
        }

        $fqdnwithspaceprefix = ' '.$fqdn;
        if (strpos($this->requiredsrifqdns, $fqdnwithspaceprefix) === false) {
            $this->requiredsrifqdns .= $fqdnwithspaceprefix;
        }
    }

    /**
     * Set the Upgrade-Insecure-Requests policy directive.
     * This directive makes the user-agent rewrite all resources starting with http:// request httpS:// resources on the page.
     * Specifications: http://www.w3.org/TR/upgrade-insecure-requests/
     * Demo page: https://googlechrome.github.io/samples/csp-upgrade-insecure-requests/index.html
     * Status: Candidate Recommendation.
     *
     * @param bool Should the upgrade-insecure-requests directive been added to the content security policy header.
     */
    public function setUpgradeInsecureRequests($upgradeinsecurerequests = true)
    {
        if (!is_bool($upgradeinsecurerequests)) {
            throw new InvalidArgumentException('upgradeinsecurerequests needs to be a boolean.');
        }

        $this->upgradeinsecurerequests = $upgradeinsecurerequests;
    }

    /**
     * Set the block-all-mixed-content Security Policy Level 3 directive to avoid loading insecure 
     * content on a secure origin. Without the this set to true passive content over insecure http 
     * could still be not blocked. Passive content is: <img> src, <audio> src and <video> src.
     * Status: Candidate recommendation:.
     *
     * @param bool $blockmixedcontent True to never load any content(strict mode) over http:// on the current page if loaded over https.
     */
    public function setBlockMixedContent($blockmixedcontent = true)
    {
        if (!is_bool($blockmixedcontent)) {
            throw new InvalidArgumentException('blockmixedcontent needs to be a boolean.');
        }

        $this->blockmixedcontent = $blockmixedcontent;
    }

    /**
     * Check if directive value is valid as value.
     *
     * @param string $directivevalue The directive value to check.
     * @return bool
     */
    private function isValidDirectiveValue($directivevalue)
    {
        if (strpos($directivevalue, ';') !== false ||
            strpos($directivevalue, "\n") !== false ||
            strpos($directivevalue, "\r") !== false) {
            return false;
        }

        return true;
    }

    /**
     * Check if the provide value is a valid fully qualified domain name.
     * original code from http://stackoverflow.com/questions/1755144/how-to-validate-domain-name-in-php
     *
     * @param string $fqdnvalue
     * @return bool True if fqdnvalue is a valid fully qualified domain name.
     */
    private function isValidFQDN($fqdnvalue)
    {
        return (preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $fqdnvalue) &&
                preg_match("/^.{1,253}$/", $fqdnvalue) &&
                preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $fqdnvalue));
    }
}
