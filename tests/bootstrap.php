<?php

use Defuse\Crypto\Key;
use Symfony\Component\Dotenv\Dotenv;

require dirname(__DIR__).'/vendor/autoload.php';

(new Dotenv())->bootEnv(dirname(__DIR__).'/.env');

if ($_SERVER['APP_DEBUG']) {
    umask(0000);
}

// .env.test ships with OAUTH_ENCRYPTION_KEY=GENERATE_AT_RUNTIME so that no
// real defuse key is committed to the repo. Generate one fresh per test run.
$encKey = $_SERVER['OAUTH_ENCRYPTION_KEY'] ?? $_ENV['OAUTH_ENCRYPTION_KEY'] ?? '';
if ($encKey === 'GENERATE_AT_RUNTIME') {
    $generated = Key::createNewRandomKey()->saveToAsciiSafeString();
    putenv("OAUTH_ENCRYPTION_KEY={$generated}");
    $_SERVER['OAUTH_ENCRYPTION_KEY'] = $generated;
    $_ENV['OAUTH_ENCRYPTION_KEY'] = $generated;
}
