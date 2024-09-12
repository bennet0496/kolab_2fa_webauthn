#!/usr/bin/env php
<?php

/**
 * User preferences update script for migration of second factor configuration.
 *
 * @author Aleksander Machniak <machniak@apheleia-it.ch>
 *
 * Copyright (C) 2024, Apheleia IT AG <contact@apheleia-it.ch>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

define('INSTALL_PATH', __DIR__ . '/../../../');
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
$plugin = $rcmail->plugins->get_plugin('kolab_2fa');

$config = [
    'totp' => ['digest' => 'sha1', 'digits' => 6],
    'hotp' => ['digest' => 'sha1', 'digits' => 6],
];

foreach ($config as $driver => $conf) {
    $driver_config = $rcmail->config->get('kolab_2fa_' . $driver);
    if (!empty($driver_config)) {
        $config[$driver] = array_merge($conf, array_intersect_key($driver_config, $conf));
    }
}

$sql_result = $db->query('SELECT * FROM ' . $db->table_name('users', true) . ' ORDER BY user_id');

while ($sql_result && ($sql_arr = $db->fetch_assoc($sql_result))) {
    $user = new rcube_user($sql_arr['user_id'], $sql_arr);
    $prefs = $user->get_prefs();

    if (!empty($prefs['kolab_2fa_blob'])) {
        echo 'Updating prefs for user ' . $sql_arr['user_id'] . '...';

        foreach ($prefs['kolab_2fa_blob'] as $key => $value) {
            [$driver] = explode(':', $key);
            if (!empty($config[$driver])) {
                $prefs['kolab_2fa_blob'][$key] += $config[$driver];
            }
        }

        if ($user->save_prefs($prefs, true)) {
            echo " DONE\n";
        } else {
            echo " FAILED\n";
            exit;
        }
    }
}
