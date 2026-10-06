#!/usr/bin/env php
<?php

const INSTALL_PATH = __DIR__ . '/../../../';
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

if (count($argv) > 1) {
  $query = implode(" OR ", array_fill(0, count($argv) - 1, "username LIKE concat('%',?,'%')"));
  $sql_result = $db->query('SELECT * FROM ' . $db->table_name('users', true) . ' WHERE '.$query. ' ORDER BY user_id', array_slice($argv, 1));
} else {
  $sql_result = $db->query('SELECT * FROM ' . $db->table_name('users', true) . ' ORDER BY user_id');
}

while ($sql_result && ($sql_arr = $db->fetch_assoc($sql_result))) {
    $user = new rcube_user($sql_arr['user_id'], $sql_arr);
    $prefs = $user->get_prefs();

    $_SESSION['username'] = $user->get_username();
    $rcmail->user = $user;

    printf("User: %s (%s)%s", $user->get_username(), $user->get_identity()['name'], PHP_EOL);
    foreach($plugin->get_factors() as $factor){
        $driver = $plugin->get_driver($factor);
        $label = $driver->get('label') ?? $plugin->gettext($driver->method);
        printf("\t%s (%s)%s", $factor, $label, PHP_EOL);
    }
}
