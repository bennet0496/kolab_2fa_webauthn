#!/usr/bin/env php
<?php

//const INSTALL_PATH = __DIR__ . '/../../../';
const INSTALL_PATH = '/home/bbecker/Projects/roundcubemail-1.7.1/';
ini_set('display_errors', 1);

require_once INSTALL_PATH . 'program/include/clisetup.php';

// connect to database
$db = $rcmail->get_dbh();
$db->db_connect('w');

if (!$db->is_connected() || $db->is_error()) {
    die("No DB connection\n");
}

// Load the plugin to load its configuration
$rcmail->plugins->load_plugin('kolab_2fa', true, true);
/**
 * @var kolab_2fa $plugin
 */
$plugin = $rcmail->plugins->get_plugin('kolab_2fa');
$plugin->init();
$plugin->add_texts('localization/');

if (count($argv) != 3) {
    printf("Usage: %s username method:id", $argv[0]);
    exit(-1);
}

$sql_result = $db->query('SELECT * FROM ' . $db->table_name('users', true) . ' ORDER BY user_id');

if ($sql_result){
    $sql_arr = $db->fetch_assoc($sql_result);
    $user = new rcube_user($sql_arr['user_id'], $sql_arr);
    $prefs = $user->get_prefs();

    $_SESSION['username'] = $user->get_username();
    $rcmail->user = $user;

    if (in_array($argv[2], $plugin->get_factors())) {
        $driver = $plugin->get_driver($argv[2]);
        $label = $driver->get('label') ?? $plugin->gettext($driver->method);
        if ($driver->clear() && $driver->commit()) {
            printf("Factor %s (%s) deleted successfully for user %s%s",$argv[2], $label, $user->get_username(), PHP_EOL);
        } else {
            printf("Error while deleting %s for user %s%s",$argv[2], $user->get_username(), PHP_EOL);
        }
    } else {
        printf("Method %s not found for user %s", $argv[2], $user->get_username());
    }
}
