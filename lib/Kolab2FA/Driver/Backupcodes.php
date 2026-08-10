<?php

/**
 * Kolab 2-Factor-Authentication Backupcodes driver implementation
 *
 * @author Bennet Becker <dev@bennet.cc>
 *
 * Copyright (C) 2015, Bennet Becker <dev@bennet.cc>
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


use Random\RandomException;

class Backupcodes extends DriverBase
{
    public string $method = 'backupcodes';

    protected array $config = [
        'length'   => 16,
        'count'    => 4,
        'alphabet' => 'acbdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
    ];

    /**
     *
     */
    public function init($config): void
    {
        parent::init($config);

        $this->user_settings += [
            'codes' => [
                'type'      => 'array',
//                'private'   => true,
                'label'     => 'codes',
                'generator' => 'generate_codes',
                'editable' => false,
                'readonly' => true,
            ],
//            'label' => [
//                'type' => 'text',
//                'label' => 'label',
//                'editable' => false,
//                'hidden' => false,
//            ],
        ];

        unset($this->user_settings['label']);
    }

    /**
     *
     */
    public function verify(string $code): bool
    {
        $codes = $this->get('codes');

        $success = false;

        for ($i = 0; $i < $this->config['count']; $i++) {
            if(hash_equals($codes[$i], $code)) {
                $success = true;
                // code is used now
                $codes[$i] = "";
            }
        }
        // we tested an empty code
        // checking last to have time constant behaviour
        if (hash_equals("", $code)) {
            $success = false;
        }

        $this->set('codes', $codes, true);
        $this->commit();

        return $success;
    }

    /**
     * @throws RandomException
     */
    public function generate_codes(): array {
        $codes = [];

        for ($i = 0; $i < $this->config['count']; $i++) {
            $code = "";
            for ($j = 0; $j < $this->config['length']; $j++) {
                $code .= substr(
                    $this->config['alphabet'],
                    random_int(0, strlen($this->config['alphabet']) - 1),
                    1);
            }
            $codes[] = $code;
        }

        return $codes;
    }

    /**
     * @override
     */
    public function set($key, $value, $persistent = true): bool
    {
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

    public function is_direct(): bool
    {
        // TODO: Implement is_direct() method.
        return false;
    }
}
