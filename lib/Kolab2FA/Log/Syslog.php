<?php

/**
 * Kolab 2-Factor-Authentication Logging class to log messages
 * through the Roundcube logging facilities.
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

namespace Kolab2FA\Log;


class Syslog implements Logger
{
    protected string $name = 'Kolab2FA';
    protected int $level = LOG_INFO;

    /** @noinspection PhpUnused */
    public function set_name($name): void
    {
        $this->name = $name;
    }

    /** @noinspection PhpUnused */
    public function set_level($level): void
    {
        $this->level = $level;
    }

    /** @noinspection PhpUnused */
    public function log($level, $message): void
    {
        if ($level >= $this->level) {
            if (!is_string($message)) {
                $message = var_export($message, true);
            }

            syslog($level, '[' . $this->name . '] ' . $message);
        }
    }
}
