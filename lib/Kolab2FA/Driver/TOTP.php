<?php

/**
 * Kolab 2-Factor-Authentication TOTP driver implementation
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

use OTPHP\TOTPInterface;

class TOTP extends DriverBase
{
    public string $method = 'totp';

    protected array $config = [
        'digits'   => 6,
        'interval' => 30,
        'digest'   => 'sha1',
        'window'   => 5
    ];

    protected array $config_keys = ['digits', 'digest'];
    protected TOTPInterface $backend;

    /**
     *
     * @throws \Exception
     */
    public function init($config): void
    {
        parent::init($config);

        $this->user_settings += [
            'secret' => [
                'type'      => 'text',
                'private'   => true,
                'label'     => 'secret',
                'generator' => 'generate_secret',
            ],
        ];

        if (!in_array($this->config['digest'], ['md5', 'sha1', 'sha256', 'sha512'])) {
            throw new \Exception("'{$this->config['digest']}' digest is not supported.");
        }

        if (!is_numeric($this->config['digits']) || $this->config['digits'] < 1) {
            throw new \Exception('Digits must be at least 1.');
        }

        if (!is_numeric($this->config['interval']) || $this->config['interval'] < 10) {
            throw new \Exception('Interval must be at least 10.');
        }

        if (!is_numeric($this->config['window']) || $this->config['window'] < 1) {
            throw new \Exception('Window must be at least 0.');
        }

        if ($this->hasSemicolon($this->config['issuer'])) {
            throw new \Exception('Issuer must not contain a semi-colon.');
        }

        // copy config options
        $this->backend = \OTPHP\TOTP::create(
            null, //secret
            $this->config['interval'], // period
            $this->config['digest'], // digest
            $this->config['digits'] // digits
        );

        $this->backend->setIssuer($this->config['issuer']);
        $this->backend->setIssuerIncludedAsParameter(true);
    }

    /**
     *
     */
    public function verify(string $code): bool
    {
        // get my secret from the user storage
        $secret = $this->get('secret');

        if (!strlen($secret)) {
            return false;
        }

        $this->backend->setLabel($this->get('username'));
        $this->backend->setSecret($secret);


        $timestamp = time();
        // - 'window' is number as codes concurrently valid (similar to libpam_google_authenticator).
        // - one code is always the current.
        // - for odd windows, we have therefore an even number of additionally valid codes.
        //   i.e. same amount of past and future valid codes
        // - for even windows, we have therefore an odd number of additionally valid codes.
        //   So we round-up the past codes and round down the future codes, asuming it is
        //   slightly more likely for the clock to lack behind on the users device
        $past = ceil(($this->config['window'] - 1) / 2);
        $future = floor(($this->config['window'] - 1) / 2);

        $timestamps = range(
            $timestamp-$past*$this->config['interval'],
            $timestamp+$future*$this->config['interval'],
            $this->config['interval']);

        $result = array_map(fn($t) => $this->backend->verify($code, $t), $timestamps);

        return in_array(true, $result);
    }

    /**
     * Get the provisioning URI.
     */
    public function get_provisioning_uri()
    {
        if (!$this->get('secret')) {
            // generate new secret and store it
            $this->set('secret', $this->get('secret', true));
            $this->set('created', $this->get('created', true));
            $this->commit();
        }

        // TODO: deny call if already active?

        $this->backend->setLabel($this->get('username'));
        $this->backend->setSecret($this->get('secret'));

        return $this->backend->getProvisioningUri();
    }
}
