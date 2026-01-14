<?php

/**
 * Kolab 2-Factor-Authentication Yubikey driver implementation
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

namespace Kolab2FA\Driver;

use Yubikey\Validate;

class Yubikey extends DriverBase
{
    public string $method = 'yubikey';

    protected mixed $backend;

    /**
     *
     */
    public function init($config): void
    {
        parent::init($config);

        $this->user_settings += [
            'yubikeyid' => [
                'type'     => 'text',
                'editable' => true,
                'label'    => 'secret',
            ],
        ];

        // initialize validator
        $this->backend = new Validate($this->config['apikey'], $this->config['clientid']);

        // set configured validation hosts
        if (!empty($this->config['hosts'])) {
            $this->backend->setHosts((array)$this->config['hosts']);
        }

        if (isset($this->config['use_https'])) {
            $this->backend->setUseSecure((bool)$this->config['use_https']);
        }
    }

    /**
     *
     */
    public function verify(string $code, int $timestamp = null): bool
    {
        error_log("Yubikey::verify() was called");
        // get my secret from the user storage
        $keyid = $this->get('yubikeyid');
        $pass  = false;

        if (!strlen($keyid)) {
            return false;
        }

        // check key prefix with associated Yubikey ID
        if (str_starts_with($code, $keyid)) {
            try {
                $response = $this->backend->check($code);
                $pass     = $response->success() === true;
            } catch (\Exception) {
                // TODO: log exception
            }
        }

        return $pass;
    }

    /**
     * @override
     */
    public function set($key, $value, $persistent = true): bool
    {
        if ($key == 'yubikeyid' && strlen($value) > 12) {
            // verify the submitted code
            try {
                $response = $this->backend->check($value);
                if ($response->success() !== true) {
                    // TODO: report error
                    return false;
                }
            } catch (\Exception) {
                return false;
            }

            // truncate the submitted yubikey code to 12 characters
            $value = substr($value, 0, 12);
        }
        // invalid or no yubikey token provided
        elseif ($key == 'yubikeyid') {
            return false;
        }

        return parent::set($key, $value, $persistent);
    }

    /**
     * @override
     */
    protected function set_user_prop($key, $value): bool
    {
        // set created timestamp
        if ($key !== 'created' && !isset($this->created)) {
            parent::set_user_prop('created', $this->get('created', true));
        }

        return parent::set_user_prop($key, $value);
    }
}
