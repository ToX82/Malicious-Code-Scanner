<?php
/*
Name: PHP Malicious Code Scanner
Original code URI: http://www.mikestowe.com/phpmalcode
URI: https://github.com/mikeybeck/Malicious-Code-Scanner
Description: The PHP Malicious Code Scanner checks all files for one of the most common malicious code attacks,
the eval( base64_decode() ) attack...
Version: 1.3.2 alpha
Authors: Michael Stowe, Phil Emerson, Mikey Beck
Author URI: http://www.mikestowe.com
Credits: Based on the idea of Er. Rochak Chauhan (http://www.rochakchauhan.com/), rewritten for use with a cron job
License: GPL-2
 */

// Configuration Settings
define('VERBOSE_OUTPUT', false);
define('SEND_EMAIL_ALERTS_TO', 'youremail@example.com');
define('SEND_EMAIL', false);
define('DISPLAY_RESULTS', true);
define('DETECT_LONG_LINES', false);
define('LONG_LINE_THRESHOLD', 350);
define('FILES_TO_MATCH', '#\.(php|php4|php5|php7|php8|phtml|html|htaccess)#');
define('IGNORE_LINK', true);
define('WORDPRESS', true);
define('PASSWORD', 'mysupersecretpassword');

class PhpMalCodeScan
{
    private $infectedFiles = [];
    private $scannedDir = '';
    private $baseDir = '';
    private $scannedFiles = [];
    private $scanPatterns = [
        '/eval\(base64/i' => 'eval(base64())',
        '/gzinflate\(base64/i' => 'gzinflate(base64())',
        '/leafmailer/i' => 'leafmailer',
        '/cmsmap/i' => 'cmsmap',
        '/WordPress Shell/i' => 'Wordpress Shell',
        '/<\?php[\s]{80}/i' => 'PHP tag with 80+ spaces',
        '/if\(isset\($_GET\[[a-z][0-9][0-9]+/i' => 'Direct access to $_GET',
        '/;@ini/i' => 'Ini file',
        '/((?<![a-z0-9_])eval\((base64|eval|\$_|\$\$|\$[A-Za-z_0-9\{]*(\(|\{|\[)))|(\$_COOKIE\[[\'"a-z0-9_]+\]\()/i' => 'Multiple pattern',
        '/(\\x[a-z0-9]{1,3}\\x[a-z0-9]{1,3})|(chr\([0-9]{1,3}\)\.chr\([0-9]{1,3}\))/i' => 'Multiple pattern 2',
        '/\) \% 3;if \(/' => '3;if',
        '/=\$GLOBALS;\${"\\\/' => 'Accessing $GLOBALS',
        '/base64_decode\(\$_POST/i' => 'base64_decode($_POST)',
        '/@include /i' => 'Suspect Include',
        '/\\b[a-z0-9_]{1,15}\\(\\$[a-z_]{1,15}\\[\\d{1,2}\\]\\(\\$_/i' => 'Potentially Obfuscated PHP command',
        '/<script[^>]+eval\\s*\\(/i' => 'Potentially Obfuscated JavaScript',
        '/\\b(?:system|exec|passthru|shell_exec)\\s*\\(\\s*\\$_(GET|POST|REQUEST)\\[\\s*[\'"]cmd[\'"]\\s*\\]/i' => 'Command Execution via URL',
        '/<\?php[\t]{25}/i' => 'PHP tag with 25+ tabs',

        '/0x84;/i' => 'Comment',
    ];

    private $filePatterns = [
        '.js.php' => 'Suspicious Fake JavaScript file',
    ];

    public function __construct()
    {
        $doScan = true;

        if (!$this->isCommandLineInterface()) {
            $pass = $_GET['pass'] ?? '';
            if ($pass !== PASSWORD) {
                die();
            }

            // Get list of files & directories up one level
            $dirs = scandir(dirname(__FILE__) . '/..');

            echo "<form name='dirselectform' action='phpMalCodeScanner.php?pass=" . $pass . "' method='POST'>";
            echo "<select name='dirselect'>";
            foreach ($dirs as $dir) {
                echo dirname(__FILE__) . '/../' . $dir;
                if (is_dir(dirname(__FILE__) . '/../') . $dir) {
                    echo "<option value='" . $dir . "'>" . $dir . "</option>";
                }
            }
            echo "</select>";
            echo "<input type='submit'>";
            echo "</form>";

            $doScan = false;
            if (isset($_POST['dirselect'])) {
                $dir = '/../' . $_POST['dirselect'];
                $this->scannedDir = $dir;
                $doScan = true;
            }
        } else {
            // Get first argument passed through command line
            if (!empty($_SERVER['argv'])) {
                $dir = '/' . ($_SERVER['argv'][1]);
            }
        }

        if ($doScan) {
            $this->baseDir = dirname(__FILE__) . ($dir ?? '');
            $this->scan(dirname(__FILE__) . ($dir ?? ''));
            $this->sendAlert();
        }
    }

    private function isCommandLineInterface()
    {
        return (php_sapi_name() === 'cli');
    }

    private function scan($dir)
    {
        $this->scannedFiles[] = $dir;
        $files = scandir($dir);

        if (!is_array($files)) {
            throw new Exception('Unable to scan directory ' . $dir . '. Please make sure proper permissions have been set.');
        }

        foreach ($files as $file) {
            if (is_file($dir . '/' . $file) && !in_array($dir . '/' . $file, $this->scannedFiles) && preg_match(FILES_TO_MATCH, $file)) {
                if (VERBOSE_OUTPUT) {
                    print "\nChecking file: $dir/$file";
                }

                $this->checkFileName($dir . '/' . $file);

                $this->check(file_get_contents($dir . '/' . $file), $dir . '/' . $file);
            } elseif (is_dir($dir . '/' . $file) && substr($file, 0, 1) != '.') {
                if (IGNORE_LINK && is_link($dir . '/' . $file)) {
                    continue;
                }
                $this->scan($dir . '/' . $file);
            }
        }
    }

    private function checkFileName($filename)
    {
        foreach ($this->filePatterns as $pattern => $descriptions) {
            if (strpos($filename, $pattern) !== false) {
                $this->infectedFiles[] = [
                    'file' => realpath($filename),
                    'line' => 0,
                    'patterns_matched' => $this->isCommandLineInterface() ? " [" . $descriptions . "]" : highlight_string($pattern, true),
                ];
            }
        }
    }

    private function check($contents, $file)
    {
        $lineEnding = $this->lineEnding();
        $this->scannedFiles[] = $file;
        $patterns = '';
        $foundLine = 0;
        $descriptions = [];
        foreach ($this->scanPatterns as $pattern => $description) {
            if (preg_match($pattern, $contents, $matches, PREG_OFFSET_CAPTURE)) {
                if ($file !== __FILE__) {
                    $offset = $matches[0][1];
                    $foundLine = substr_count(substr($contents, 0, $offset), "\n") + 1;

                    $patterns .= $pattern;
                    $descriptions[] = $description;
                }
            }
        }
        if (!empty($patterns)) {
            // Find out in which line the pattern was found
            $this->infectedFiles[] = [
                'file' => realpath($file),
                'line' => $foundLine,
                'patterns_matched' => $this->isCommandLineInterface() ? " [" . implode(", ", $descriptions) . "]" : highlight_string($patterns, true),
            ];
        }

        if (WORDPRESS) {
            $filename = basename($file);

            if (strpos($file, "wp-content/uploads/") && strpos($filename, ".php")) {
                $isPhp = false;
                // Twig cache is not to be considered
                if (strpos($file, "uploads/cache/wpml/twig/") !== false) {
                    $isPhp = true;
                }
                // Files with less than 30 bytes are not to be considered, if they only contain "Silence is golden"
                if (filesize($file) > 30) {
                    $isPhp = true;
                } else {
                    $content = file_get_contents($file);
                    if (strpos($content, "Silence is golden") === false) {
                        $isPhp = true;
                    }
                }

                if ($isPhp === true) {
                    $this->infectedFiles[] = [
                        'file' => $file,
                        'line' => $foundLine,
                        'patterns_matched' => ' [php file in a WP uploads directory]',
                    ];
                }
                return $isPhp;
            }
        }
        // If checking for long lines is not enabled, leave the function now
        if (!DETECT_LONG_LINES) {
            return false;
        }

        // Detect long lines must be enabled - split the file and check how long each line is.
        $buffer = preg_split('#\r\n|\n|\r#', trim($contents));
        $count = 1;
        foreach ($buffer as $line) {
            // Have we found a line longer than the threshold?
            if (strlen($line) > LONG_LINE_THRESHOLD) {
                // Yes - add the file to the infected files list
                $this->infectedFiles[] = $file . "\nLong line found on line $count\n    ---    " .
                substr($line, -100) . "\n";
                // Clean up.
                $buffer = null;
                unset($buffer);
                // As we've already found a long line, there's no need to check for others.
                return true;
            }
            $count++;
        }

        // Nothing detected in the current file - return false.
        return false;
    }

    private function lineEnding()
    {
        if ($this->isCommandLineInterface()) {
            return "\n";
        }
        return '<br>';
    }

    private function sendAlert()
    {
        $lineEnding = $this->lineEnding();
        $totalInfectedFiles = count($this->infectedFiles);

        if ($totalInfectedFiles != 0) {
            $this->println('== MALICIOUS CODE FOUND ==', 'red');
            $this->println("The following $totalInfectedFiles files appear to be infected:$lineEnding$lineEnding");

            foreach ($this->infectedFiles as $inf) {
                $fullPath = realpath($inf['file']);
                $filename = str_replace($this->baseDir, '', $fullPath);
                $line = ($inf['line']) ? ' (line: ' . $inf['line'] . ')' : '';
                $pattern = $inf['patterns_matched'];
                $this->println(" - $filename $line $pattern $lineEnding", 'green');
            }

            $this->println("$lineEnding$totalInfectedFiles files appear to be infected. $lineEnding", 'red');

            if (SEND_EMAIL) {
                mail(SEND_EMAIL_ALERTS_TO, 'Malicious Code Found!', 'Malicious code found in the scanned files.', 'FROM:');
            }
        } else {
            $this->println('No infected files found in ' . $this->baseDir);
        }
    }

    private function println($text, $color = null)
    {
        $coloredText = $text;

        if ($color) {
            $coloredText = "\033[" . $this->getForegroundColorCode($color) . "m$text\033[0m";
        }

        echo $coloredText;
    }

    private function getForegroundColorCode($color)
    {
        $colors = [
            'black' => '0;30',
            'red' => '0;31',
            'green' => '0;32',
            'yellow' => '0;33',
            'blue' => '0;34',
            'purple' => '0;35',
            'cyan' => '0;36',
            'white' => '1;37',
        ];

        return isset($colors[$color]) ? $colors[$color] : '';
    }
}

// Initialize Class
ini_set('memory_limit', '-1');
new PhpMalCodeScan();
