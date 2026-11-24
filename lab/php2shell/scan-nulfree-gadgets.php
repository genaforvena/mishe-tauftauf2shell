<?php
// php2shell — NUL-free gadget scanner for the rung-5 splice lane.
// A session-decode gadget payload must be NUL-free (multipart filename
// channel), so every $this->prop referenced by the magic method must be
// public or undeclared (dynamic). Token-based, no class loading.
//
// Usage: php scan-nulfree-gadgets.php <vendor-dir> [<more-dirs>...]

function candidates(string $file): array {
    $src = @file_get_contents($file);
    if ($src === false) return [];
    if (strpos($src, '__destruct') === false && strpos($src, '__wakeup') === false) return [];
    if (strpos($src, '__unserialize') !== false) return []; // guard-throw risk: skip
    $toks = @token_get_all($src);
    if (!$toks) return [];
    $out = [];
    $n = count($toks);
    $class = null; $depth = 0; $inMethod = false; $method = '';
    $propVis = [];        // prop name => visibility for current class
    $curVis = 'public';
    for ($i = 0; $i < $n; $i++) {
        $t = $toks[$i];
        if (is_array($t)) {
            [$id, $text] = $t;
            if ($id === T_CLASS || $id === T_TRAIT) { $class = null; $propVis = []; }
            if ($id === T_STRING && $class === null && $depth === 0) {
                // class name heuristic: previous meaningful token was class/trait
            }
            if ($id === T_PUBLIC) $curVis = 'public';
            if ($id === T_PROTECTED) $curVis = 'protected';
            if ($id === T_PRIVATE) $curVis = 'private';
            if ($id === T_VARIABLE && $class !== null && $depth === 1) {
                // class-level property declaration
                $propVis[substr($text, 1)] = $curVis;
            }
            if ($id === T_FUNCTION) {
                // next T_STRING is the function name
                for ($j = $i + 1; $j < $n; $j++) {
                    if (is_array($toks[$j]) && $toks[$j][0] === T_STRING) {
                        $method = $toks[$j][1];
                        if (in_array($method, ['__destruct', '__wakeup'], true)) {
                            $out[] = ['class' => $class, 'method' => $method, 'start' => $i];
                        }
                        break;
                    }
                    if (is_array($toks[$j]) && in_array($toks[$j][0], [T_PUBLIC, T_PROTECTED, T_PRIVATE, T_STATIC, T_ABSTRACT, T_FINAL], true)) continue;
                    if (!is_array($toks[$j]) || !in_array($toks[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) break;
                }
            }
            if ($id === T_STRING && ($text === '__destruct' || $text === '__wakeup')) {
                // track current class name for the hit we appended above
                foreach ($out as $k => $o) { if ($o['class'] === null) $out[$k]['class'] = $class; }
            }
        } else {
            if ($t === '{') {
                $depth++;
                if ($depth === 2) {
                    // entering a method body: find owning method name
                }
            }
            if ($t === '}') $depth--;
            if ($depth === 1 && $class !== null) {
                // method-body tokens flow through here; collect $this->prop refs
            }
        }
    }
    return $out;
}

$roots = array_slice($argv, 1);
foreach ($roots as $root) {
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) {
        if (!$f->isFile() || $f->getExtension() !== 'php') continue;
        $p = $f->getPathname();
        if (preg_match('/test/i', $p)) continue;
        $src = @file_get_contents($p);
        if ($src === false) continue;
        if (strpos($src, '__destruct') === false && strpos($src, '__wakeup') === false) continue;
        if (strpos($src, '__unserialize') !== false) continue;
        // --- simple per-class analysis via token stream, one class block at a time
        $toks = @token_get_all($src);
        if (!$toks) continue;
        $n = count($toks);
        $classes = []; // idx => name
        $cur = null;
        $vis = 'public';
        $props = [];
        for ($i = 0; $i < $n; $i++) {
            $t = $toks[$i];
            if (is_array($t)) {
                if ($t[0] === T_CLASS) {
                    for ($j = $i + 1; $j < $n && $j < $i + 8; $j++) {
                        if (is_array($toks[$j]) && $toks[$j][0] === T_STRING) { $cur = $toks[$j][1]; break; }
                    }
                }
                if ($t[0] === T_PUBLIC || $t[0] === T_PROTECTED || $t[0] === T_PRIVATE) $vis = strtolower(trim($t[1]));
                if ($t[0] === T_VARIABLE && $cur !== null) {
                    $name = substr($t[1], 1);
                    // property declaration iff next non-ws token is ';' or '=' and we are at class level (depth 1)
                    $j = $i + 1;
                    while ($j < $n && is_array($toks[$j]) && in_array($toks[$j][0], [T_WHITESPACE, T_COMMENT], true)) $j++;
                    if (isset($toks[$j]) && (is_string($toks[$j]) && ($toks[$j] === ';' || $toks[$j] === '='))) {
                        $props[$cur][$name] = $vis;
                    }
                }
            }
        }
        // find magic methods and referenced props
        $inMagic = false; $magic = ''; $brace = 0; $refs = [];
        for ($i = 0; $i < $n; $i++) {
            $t = $toks[$i];
            if (is_array($t) && $t[0] === T_CLASS) {
                for ($j = $i + 1; $j < $n && $j < $i + 8; $j++) {
                    if (is_array($toks[$j]) && $toks[$j][0] === T_STRING) { $cur = $toks[$j][1]; break; }
                }
            }
            if (is_array($t) && $t[0] === T_FUNCTION) {
                for ($j = $i + 1; $j < $n && $j < $i + 10; $j++) {
                    if (is_array($toks[$j]) && $toks[$j][0] === T_STRING) {
                        $magic = in_array($toks[$j][1], ['__destruct', '__wakeup'], true) ? $toks[$j][1] : '';
                        break;
                    }
                }
                $refs = []; $brace = 0; $inMagic = ($magic !== '');
            }
            if (!$inMagic) continue;
            if (is_array($t) && $t[0] === T_OBJECT_OPERATOR && $brace > 0) {
                for ($j = $i + 1; $j < $n; $j++) {
                    if (is_array($toks[$j]) && in_array($toks[$j][0], [T_WHITESPACE, T_COMMENT], true)) continue;
                    if (is_array($toks[$j]) && $toks[$j][0] === T_STRING) $refs[] = $toks[$j][1];
                    break;
                }
            }
            if (is_string($t)) {
                if ($t === '{') $brace++;
                if ($t === '}') { $brace--; if ($brace === 0 && $refs !== []) {
                    // method complete: analyze
                    $bad = [];
                    foreach ($refs as $r) {
                        if ($r === 'this') continue;
                        $v = $props[$cur][$r] ?? 'dynamic';
                        if ($v === 'private' || $v === 'protected') $bad[] = "$r($v)";
                    }
                    if (!$bad) {
                        echo "$p class=$cur $magic refs=" . implode(',', array_unique($refs)) . "\n";
                    }
                    $refs = []; $inMagic = false;
                }}
            }
        }
    }
}
