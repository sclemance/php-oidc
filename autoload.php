<?php
/**
 * Non-Composer autoloader.
 *
 * If you are using Composer, ignore this file and rely on `vendor/autoload.php`.
 * For projects that do NOT use Composer (e.g. simple shared-hosting apps), just:
 *
 *     require '/path/to/php-oidc/autoload.php';
 *     use Sclemance\Oidc\Oidc;
 *
 * This registers a PSR-4 autoloader for the Sclemance\Oidc namespace mapped to src/.
 */

spl_autoload_register(static function (string $class): void {
    $prefix = 'Sclemance\\Oidc\\';
    $len = strlen($prefix);
    if (strncmp($class, $prefix, $len) !== 0) {
        return;
    }
    $relative = substr($class, $len);
    $path = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require $path;
    }
});
