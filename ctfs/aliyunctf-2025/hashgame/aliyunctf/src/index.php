<?php
$func_template = 'function check($file_hash, %s) { if ($file_hash !== "5baf19ce6561538119dfe32d561d6ab8509703606f768fea72723a01ee4264b7") { echo "%s not cached"; } }';
$cached_key = isset($_GET['c']) ? $_GET['c'] : '$f_0';
if (!preg_match('/^[a-zA-Z0-9_\$]{1,5}$/', $cached_key)) {
        die('Invalid cached key');
}
$func = sprintf($func_template, $cached_key, $cached_key);
eval($func);
if (isset($_GET['h']) && isset($_GET['algo']) && isset($_GET['file'])) {
    $file_hash = hash_file($_GET['algo'], $_GET['file']);
    check($file_hash, $_GET['file']);
} else {
    phpinfo();
}

$base_string = "aliyunctf{" . str_repeat("\x00", 15) . "}\n";
$hashes = [];

$hashes[] = hash($_GET['algo'], $base_string);

for ($i = 0; $i < 15 * 8; $i++) {
    $s = str_repeat("\x00", 15);
    $byteIndex = intdiv($i, 8);
    $bitPosition = 7 - ($i % 8);
    
    $s[$byteIndex] = chr(ord($s[$byteIndex]) | (1 << $bitPosition));
    
    $s = "aliyunctf{" . $s . "}\n";
    
    $hashes[] = hash($_GET['algo'], $s);
}

print_r($hashes);

?>