<?php
$wrappers = stream_get_wrappers();
foreach ($wrappers as $wrapper) {
    if ($wrapper === 'file') {
        continue;
    }
    @stream_wrapper_unregister($wrapper);
}
?>