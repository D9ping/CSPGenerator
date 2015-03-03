<?php 
/*
Copyright (c) 2014-2015, Tom
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

    private $reportonly = FALSE;

    private $defaultsrc = " 'none'";

    private $stylesrc = " 'self'";

    private $imagesrc = " 'self'";

    private $scriptsrc = " 'self'";

    private $scriptsrcnonce = '';

    private $connectsrc = '';

    private $mediasrc = '';

    private $fontsrc = '';

    private $framesrc = '';

    private $childsrc = '';

    private $frameancestors = '';

    private $objectsrc = '';

    private $plugintypes = '';

    private $formaction = " 'self'";

    private $sandboxoptions = '';

    private $reffererpolicy = '';

    private $reflectedxss = 'filter';

    private $reporturi = '';

    /**
     * Create a new instance of CSPGenerator class.
     */
    public function __construct() {
    }

    /**
     * Get instance of CSPGenerator class.
     */
    public static function getInstance() {
        if (empty(self::$instance)) {
            self::$instance = new CSPGenerator();
        }

        return self::$instance;
    }

    /**
     * Set the url to where to report violations of the Content Security Policy.
     */
    public function setReporturi($reporturi) {
        $this->reporturi = $reporturi;
    }

    /**
     * Set report only mode.
     */
    public function setReportOnly() {
        $this->reportonly = TRUE;
    }

    /**
     * Set reflected-xss content security policy 1.1>= policy setting. (Experimental directive)
     * @param string $reflectedxss The experimental reflected-xss policy directive. This can be allow, filter(default) or block.
     */
    public function setReflectedxss($reflectedxss) {
        $this->reflectedxss = $reflectedxss;
    }

    /**
     * Parse user-agent header and set proper Content Security Policy header,
     * X-Frame-Options header and X-XSS-Protection header based on the browser and browser version.
     */
    public function Parse() {
        $useragentinfo = $this->getBrowserInfo();
        if ($useragentinfo['browser'] === 'chrome') {
            // Disable content security policy violation reporting if chrome is used
            // because google chrome is causing false positives with google translate translating the page.
            $this->reporturi = NULL;
        }

        $cspheader = 'Content-Security-Policy: ';
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
            $cspheader .= 'allow ' . $this->defaultsrc;
        } elseif ( ($useragentinfo['browser'] === 'chrome' && $useragentinfo['version'] <= 24 && $useragentinfo['version'] >= 14) || 
                   ($useragentinfo['browser'] === 'safari' && $useragentinfo['version'] >= 6 && $useragentinfo['version'] < 7) ) {
            // Safari 5.0/5.1 X-WebKit-CSP implementation is badly broken it blocks permited\whitelisted things so it's not usable at all.
            if ($this->reportonly) {
                $cspheader = 'X-WebKit-CSP-Report-Only: ';
            } else {
                $cspheader = 'X-WebKit-CSP: ';
            }

            $cspheader .= 'default-src' . $this->defaultsrc;
        } else {
            $cspheader .= 'default-src' . $this->defaultsrc;
        }

        if (!empty($this->stylesrc)) {
            // The obsolete decreated X-Content-Security-Policy header does not support style-src. This is not implemented.
            $cspheader .= '; style-src' . $this->stylesrc;
        }

        if (!empty($this->imagesrc)) {
            $cspheader .= '; img-src' . $this->imagesrc;
        }

        if (!empty($this->scriptsrc)) {
            $cspheader .= '; script-src' . $this->scriptsrc;
            if (!empty($this->scriptsrcnonce)) {
                $cspheader .= " 'nonce-" . $this->scriptsrcnonce . "'";
            }

            // for inline script with the X-Content-Security-Policy header use 'options inline-script'.
            if ($useragentinfo['browser'] === 'firefox' && $useragentinfo['version'] <= 22 && $useragentinfo['version'] >= 3.7) {
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
                $cspheader .= '; xhr-src' . $this->connectsrc;
            } else {
                $cspheader .= '; connect-src' . $this->connectsrc;
            }
        }

        if (!empty($this->mediasrc)) {
            $cspheader .= '; media-src' . $this->mediasrc;
        }

        if (!empty($this->fontsrc)) {
            $cspheader .= '; font-src' . $this->fontsrc;
        }

        if (!empty($this->childsrc)) {
            // Experimental, CSP Level 2 only:
            $cspheader .= '; child-src' . $this->childsrc;
        } elseif (!empty($this->framesrc)) {
            // CSP Level 1
            $cspheader .= '; frame-src' . $this->framesrc;
        }

        if (!empty($this->frameancestors)) {
            // CSP 1.1
            $cspheader .= '; frame-ancestors' . $this->frameancestors;
        }

        if (!empty($this->objectsrc)) {
            $cspheader .= '; object-src' . $this->objectsrc;
        }

        // Experimental:
        if (!empty($this->plugintypes)) {
            if ($useragentinfo['browser'] === 'opr' && $useragentinfo['version'] >= 20) {
                $cspheader .= '; plugin-types' . $this->plugintypes;
            }
        }

        // Experimental:
        if (!empty($this->reffererpolicy)) {
            $cspheader .= '; refferer ' . $this->reffererpolicy;
        }

        // Experimental:
        //if (!empty($this->formaction)) {
        //    if ($useragentinfo['browser'] === 'opr' && $useragentinfo['version'] >= 25) {
        //        $cspheader .= '; form-action' . $this->formaction;
        //   }
        //}

        // Experimental:
        //if (!empty($this->reflectedxss)) {
        //    if ($useragentinfo['browser'] === 'opr' && $useragentinfo['version'] >= 25) {
        //        $cspheader .= '; reflected-xss ' . $this->reflectedxss;
        //    }
        //}

        if (!empty($this->reporturi)) {
            if ($useragentinfo['browser'] !== 'firefox' || $useragentinfo['version'] > 22) {
                $cspheader .= '; report-uri ' . $this->reporturi;
            }
        }

        header($cspheader, TRUE);
        // Add X-Frame-Options header based on the content security policy frame-ancestors directive.
        if (strpos($this->frameancestors, "'none'") >= 0 ||
            empty($this->frameancestors) && strpos($this->defaultsrc, "'none'") >= 0) {
            header('X-Frame-Options: DENY', TRUE);
        } elseif (strpos($this->frameancestors, "'self'") >= 0 || empty($this->frameancestors)) {
            header('X-Frame-Options: SAMEORIGIN', TRUE);
        } elseif (strpos($this->frameancestors, ' *') >= 0) {
            header('X-Frame-Options: ALLOW', TRUE);
        } else {
            // ALLOW-FROM Not supported in Chrome or Safari or Opera and any Firefox less than version 18.0 and any Internet Explorer browser less than version 9.0. (source: http://erlend.oftedal.no/blog/tools/xframeoptions/)
            if (($useragentinfo['browser'] === 'firefox' && $useragentinfo['version'] >= 18) || 
                ($useragentinfo['browser'] === 'msie' && $useragentinfo['version'] >= 9)) {
                header('X-Frame-Options: ALLOW-FROM ' . $this->framesrc, TRUE);
            }
        }

        // Add X-XSS-Protection header based on CSP 1.1 settings.
        switch ($this->reflectedxss) {
            case 'filter':
                // filter is the prefered one, because mode=block can cause possible insecurity, source: http://homakov.blogspot.nl/2013/02/hacking-with-xss-auditor.html
                header('X-XSS-Protection: 1', TRUE);
                break;
            case 'allow':
                header('X-XSS-Protection: 0', TRUE);
                break;
            case 'block':
                header('X-XSS-Protection: 1; mode=block', TRUE);
                break;
        }
    }

    /**
     * Get browser name and version from user-agent header.
     * @return string[]
     */
    private function getBrowserInfo() {
        // Declare known browsers to look for
        $browsers = array('firefox', 'msie', 'safari', 'webkit', 'chrome', 'opr', 'opera', 'netscape', 'konqueror');

        // Clean up useragent and build regex that matches phrases for known browsers
        // (e.g. "Firefox/2.0" or "MSIE 6.0" (This only matches the major and minor
        // version numbers.  E.g. "2.0.0.6" is parsed as simply "2.0"
        if (!isset($_SERVER['HTTP_USER_AGENT'])) {
            return array('browser' => 'unknown', 'version' => '-1.0');
        }

        $useragent = strtolower($_SERVER['HTTP_USER_AGENT']);
        $pattern = '#(?<browser>' . join('|', $browsers) .')[/ ]+(?<version>[0-9]+(?:\.[0-9]+)?)#';
        // Find all phrases (or return empty array if none found)
        if (!preg_match_all($pattern, $useragent, $matches)) {
            if (strpos($useragent, 'Trident/') >= 0) {
                // IE 11 does not have msie in user-agent header anymore, IE developers want forcing
                // feature detecting with javascript. This is not for HTTP headers possible, 
                // because then the headers are already send. 
                // source: http://blogs.msdn.com/b/ieinternals/archive/2013/09/21/internet-explorer-11-user-agent-string-ua-string-sniffing-compatibility-with-gecko-webkit.aspx
                return array('browser' => 'msie', 'version' => '11');
            } else {
                // Unknow browser.
                return array('browser' => 'unknown', 'version' => '-1.0');
            }
        }

        // Since some UAs have more than one phrase (e.g Firefox has a Gecko phrase, Opera 7,8 have a MSIE phrase), 
        // use the last one found (the right-most one in the UA). That's usually the most correct.
        $i = count($matches['browser']) - 1;
        return array('browser' => $matches['browser'][$i], 'version' => $matches['version'][$i]);
    }

    /**
     * Set the default-src content security policy directive. We don't allow empty default policy.
     * @param string $defaultsrc The default-src policy directive. Style-src, image-src, script-src, frame-src, connect-src, font-src, objectsrc and media-src all inherit from this.
     */
    public function setDefaultsrc($defaultsrc) {
        if (empty($defaultsrc)) {
            throw new Exception('CSP default-src policy directive cannot be empty.');
        }

        $this->defaultsrc = $defaultsrc;
    }

    /**
     * Set the refferer policy, this will change the behavoir how the user-agent sends the referrer header for your origin.
     * @param string the refferer policy can be: "never", "default", "origin" or "always". 
     * Note: "always" will send the full referrer on HTTP coming from a HTTPS referrer site this is a security issue for session urls.
     */
    public function setReferrerPolicy($reffererpolicy) {
        if ($reffererpolicy === 'never' ||
            $reffererpolicy === 'default' ||
            $reffererpolicy === 'origin' ||
            $reffererpolicy === 'always') {
            $this->reffererpolicy = $reffererpolicy;
        } else {
            throw new Exception('CSP referrer policy unknown.');
        }
    }

    /**
     * Add style-src Content Security Policy Level 1 directive.
     * In Content Security Policy Level 2, the use of 'none-$nonce' and 'sha256-$hash' is allowed for whitelisted inline style= use.
     * @param string $stylesrc The style-src policy directive to add. Where to allow CSS files from use 'unsafe-inline' for style attributes in (X)HTML document.
     */
    public function addStylesrc($stylesrc) {
        if (strpos($this->stylesrc, $stylesrc) === FALSE) {
            $this->stylesrc .= ' ' . $stylesrc;
        }
    }

    /**
     * Add image-src Content Security Policy Level 1 directive.
     * @param string $imagesrc The image-src policy directive to add. Where to allow images from. Use data: for base64 data url images.
     */
    public function addImagesrc($imagesrc) {
        if (strpos($this->imagesrc, $imagesrc) === FALSE) {
            $this->imagesrc .= ' ' . $imagesrc;
        }
    }

    /**
     * Add script-src Content Security Policy Level 1 directive.
     * In Content Security Policy Level 2, the use of 'none-$nonce' and 'sha256-$hash' is allowed for whitelisted inline style= use.
     * @param string $scriptsrc The script-src policy directive to add. Use 'unsafe-inline' to allow unsafe loading of iniline scripts, use 'unsafe-eval' to allow text-to-JavaScript mechanisms like eval.
     */
    public function addScriptsrc($scriptsrc) {
        if (strpos($this->scriptsrc, $scriptsrc) === FALSE) {
            $this->scriptsrc .= ' ' . $scriptsrc;
        }
    }

    /**
     * Set a new script nonce.
     * @param bool $enablenonce Is the use of a nonces for allowed inline scripts enabled.
     * @param int  $lengthnonce The length of the nonce.
     */
    public function setScriptsrcNonce($enablenonce = TRUE, $lengthnonce = 20) {
        if ($lengthnonce < 8) {
            throw new Exception('The nonce length needs to be at least 8 characters.');
        }

        if ($enablenonce) {
            if (!function_exists('openssl_random_pseudo_bytes')) {
                throw new Exception('No secure pseudo random generator available for generating nonce.');
            }

            $this->scriptsrcnonce = substr(base64_encode(openssl_random_pseudo_bytes($lengthnonce)), 0, $lengthnonce);
        } else {
            $this->scriptsrcnonce = '';
        }
    }

    /**
     * Get the current script-src nonce.
     * @return string
     */
    public function getScriptsrcNonce() {
        if (empty($this->scriptsrcnonce)) {
            throw new Exception('No script-src nonce used.');
        }

        return $this->scriptsrcnonce;
    }

    /**
     * Add connect-src Content Security Policy Level 1 directive.
     * @param string $connectsrc The connect-src policy directive to add. Where to allow XMLHttpRequest to connect to.
     */
    public function addConnectsrc($connectsrc) {
        if (strpos($this->connectsrc, $connectsrc) === FALSE) {
            $this->connectsrc .= ' ' . $connectsrc;
        }
    }

    /**
     * Add media-src Content Security Policy Level 1 directive.
     * @param string $mediasrc The media-src policy directive to add. Where to allow to load video/audio sources from. Use mediastream: for the MediaStream API. 
     */
    public function addMediasrc($mediasrc) {
        if (strpos($this->mediasrc, $mediasrc) === FALSE) {
            $this->mediasrc .= ' ' . $mediasrc;
        }
    }

    /**
     * Add font-src Content Security Policy Level 1 directive.
     * @param string $fontsrc The font-src policy directive to add. Where to allow to load font files from.
     */
    public function addFontsrc($fontsrc) {
        if (strpos($this->fontsrc, $fontsrc) === FALSE) {
            $this->fontsrc .= ' ' . $fontsrc;
        }
    }

    /**
     * Add frame-src Content Security Policy Level 1 directive.
     * note: frame-src is decreated in Content Security Policy Level 2 in favor of the child-src directive.
     * @param string $framesrc The frame-src policy directive to add. Where to allow to load frames/iframe from.
     */
    public function addFramesrc($framesrc) {
        if (strpos($this->framesrc, $framesrc) === FALSE) {
            $this->framesrc .= ' ' . $framesrc;
        }
    }

    /**
     * Add the child-src Content Security Policy Level 2 directive. (Experimental Directive)
     * note: This directive also applies to the decreated frame-src directive.
     */
    public function addChildsrc($childsrc) {
        if (strpos($this->childsrc, $childsrc) === FALSE) {
            $this->childsrc .= ' ' . $childsrc;
        }
    }

    /**
     * Add the frame-ancestors Content Security Policy Level 2 directive. (Experimental Directive)
     * This directive does the same as the X-Frame-Options header.
     */
    public function addFrameancestors($frameancestors) {
        if (strpos($this->frameancestors, $frameancestors) === FALSE) {
            $this->frameancestors .= ' ' . $frameancestors;
        }
    }

    /**
     * Add object-src Content Security Policy Level 1 directive.
     * @param string $objectsrc The object-src policy directive to add. Where to allow to load plugins objects like flash/java applets from.
     */
    public function addObjectsrc($objectsrc) {
        if (strpos($this->objectsrc, $objectsrc) === FALSE) {
            $this->objectsrc .= ' ' . $objectsrc;
        }
    }

    /**
     * Add plugin-types Content Security Policy Level 2 directive. (Experimental Directive)
     * @param string $plugintypes The plugin-types policy directive to add. A list of MIME types (e.g. application/x-shockwave-flash) of plugins allowed to load.
     */
    public function addPlugintypes($plugintypes) {
        if (strpos($this->plugintypes, $plugintypes) === FALSE) {
            $this->plugintypes .= ' ' . $plugintypes;
        }
    }

    /**
     * Add form-action Content Security Policy Level 2 directive. (Experimental Directive)
     * @param string $formaction The form-action policy directive to add. Restricts which URIs can be used as the action of HTML form elements.
     */
    public function addFormaction($formaction) {
        if (strpos($this->formaction, $formaction) === FALSE) {
            $this->formaction .= ' ' . $formaction;
        }
    }

    /**
     * Add sandbox options to the sandbox Content Security Policy directive.
     * @param string $sandboxoption The sandbox policy directive to add. This can be: allow-forms, allow-pointer-lock, allow-popups, allow-same-origin, allow-scripts or allow-top-navigation.
     */
    public function addSandboxoption($sandboxoption) {
        if ($sandboxoption === 'allow-forms' ||
            $sandboxoption === 'allow-pointer-lock' ||
            $sandboxoption === 'allow-popups' ||
            $sandboxoption === 'allow-same-origin' ||
            $sandboxoption === 'allow-scripts' ||
            $sandboxoption === 'allow-top-navigation') {
            if (strpos($this->sandboxoptions, $sandboxoption) === FALSE) {
                $this->sandboxoptions .= ' ' . $sandboxoption;
            }
        } else {
            throw new Exception('CSP sandbox option directive unknown.');
        }
    }
}