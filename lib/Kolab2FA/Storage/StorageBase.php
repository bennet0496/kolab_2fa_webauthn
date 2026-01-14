<?php

/**
 * Abstract storage backend class for the Kolab 2-Factor-Authentication plugin
 *
 * @author Thomas Bruederli <bruederli@kolabsys.com>
 *
 * Copyright (C) 2015, Kolab Systems AG <contact@kolabsys.com>
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

namespace Kolab2FA\Storage;

use Kolab2FA\Log;

abstract class StorageBase
{
    public ?string $username = null;

    protected array $config = [];
    protected Log\Logger $logger;

    /**
     *
     * @throws Exception
     */
    public static function factory($backend, $config)
    {
        $classmap = [
            'ldap' => '\\Kolab2FA\\Storage\\LDAP',
            'roundcube' => '\\Kolab2FA\\Storage\\RcubeUser',
            'rcubeuser' => '\\Kolab2FA\\Storage\\RcubeUser',
        ];

        $cls = $classmap[strtolower($backend)];
        if ($cls && class_exists($cls)) {
            return new $cls($config);
        }

        throw new Exception("Unknown storage backend '$backend'");
    }

    /**
     * Default constructor
     * @noinspection PhpUnused
     */
    public function __construct($config = null)
    {
        if (is_array($config)) {
            $this->init($config);
        }
    }

    /**
     * Initialize the driver with the given config options
     */
    public function init(array $config): void
    {
        $this->config = array_merge($this->config, $config);

        // use syslog logger by default
        $this->set_logger(new Log\Syslog());
    }

    /**
     *
     */
    public function set_logger(Log\Logger $logger): void
    {
        $this->logger = $logger;

        if (!empty($this->config['debug'])) {
            $this->logger->set_level(LOG_DEBUG);
        } elseif (!empty($this->config['loglevel'])) {
            $this->logger->set_level($this->config['loglevel']);
        }
    }

    /**
     * Set username to store data for
     */
    public function set_username($username): void
    {
        $this->username = $username;
    }

    /**
     * Send messager to the logging system
     */
    protected function log($level, $message): void
    {
        $this->logger->log($level, $message);
    }

    /**
     * List keys holding settings for 2-factor-authentication
     */
    abstract public function enumerate();

    /**
     * Read data for the given key
     */
    abstract public function read($key);

    /**
     * Save data for the given key
     */
    abstract public function write($key, $value);

    /**
     * Remove the data stored for the given key
     */
    abstract public function remove($key);
}
