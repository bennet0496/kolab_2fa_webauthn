<?php

use Kolab2FA\Driver\DriverBase;
use Kolab2FA\Log\RcubeLogger;
use Kolab2FA\Storage\StorageBase;

/**
 * Kolab 2-Factor-Authentication plugin
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

class kolab_2fa extends rcube_plugin
{

    protected array $drivers = [];
    protected ?StorageBase $storage;

    public static function log(...$args): void
    {
        $caller = debug_backtrace();
        $file = basename($caller[0]['file']);
        foreach ($args as $arg) {
            error_log("$file:{$caller[0]['line']}:{$caller[1]['function']}() ".json_encode($arg));
        }
    }

    /**
     * Plugin init
     */
    public function init(): void
    {
        $this->load_config();
        $this->add_hook('startup', [$this, 'startup']);
        $this->add_hook('ready', [$this, 'ready']);
    }

    /**
     * Startup hook
     */
    public function startup($args)
    {
        $rcmail = rcmail::get_instance();

        // register library namespace to autoloader
        $loader = include(INSTALL_PATH . 'vendor/autoload.php');
        $loader->set('Kolab2FA', [$this->home . '/lib']);

        return $args;
    }

    /**
     * @throws Exception
     */
    protected function get_factors(): array
    {
        $rcmail = rcmail::get_instance();

        // 2a. let plugins provide the list of active authentication factors
        $lookup = $rcmail->plugins->exec_hook('kolab_2fa_lookup', [
            'user' => $_SESSION['username'],
            'host' => $_SESSION['storage_host'],
            'factors' => null,
            'check' => $rcmail->config->get('kolab_2fa_check', true),
        ]);

        $factors = [];
        if (isset($lookup['factors'])) {
            $factors = (array)$lookup['factors'];
        } // 2b. check storage if this user has 2FA enabled
        elseif ($lookup['check'] !== false && ($storage = $this->get_storage($_SESSION['username']))) {
            $factors = (array)$storage->enumerate();
        }

        return $factors;
    }

    /**
     * @throws Exception
     */
    public function ready($args) {
        $rcmail = rcmail::get_instance();

        if (!($_SESSION['kolab_2fa_login_verified'] ?? false) && !in_array($args['action'], ['plugin.kolab-2fa-login', 'keep-alive', 'refresh'])) {
            // 2a. let plugins provide user settings
            $lookup = $rcmail->plugins->exec_hook('kolab_2fa_lookup', [
                'user' => $_SESSION['username'],
                'host' => $_SESSION['storage_host'],
                'enforce' => $rcmail->config->get('kolab_2fa_enforce', false),
            ]);

            if (count($this->get_factors()) > 0) {
                // 3. flag session for 2nd factor verification
                $_SESSION['kolab_2fa_time'] = time();
                $_SESSION['kolab_2fa_nonce'] = bin2hex(openssl_random_pseudo_bytes(32));

                // 4. render to 2nd auth step
                $this->add_texts('localization/');
                $this->login_step();
            } elseif ($lookup['enforce'] && $args['action'] !== 'plugin.kolab-2fa' && $args['task'] !== 'settings') {
                // redirect to settings
                $_SESSION['kolab_2fa_setup_forced'] = true;
                $this->api->output->redirect(['task' => 'settings', 'action' => 'plugin.kolab-2fa']);
            }
        }
        elseif ($args['action'] === 'plugin.kolab-2fa-login') {
            // process 2nd factor auth step after regular login
            $this->api->output->redirect($this->login_verify($args) + ["action" => null]);
        }

        if ($args['task'] === 'settings') {
            $this->add_texts('localization/', !$this->api->output->ajax_call);
            $this->add_hook('settings_actions', [$this, 'settings_actions']);
            $this->register_action('plugin.kolab-2fa', [$this, 'settings_view']);
            $this->register_action('plugin.kolab-2fa-data', [$this, 'settings_data']);
            $this->register_action('plugin.kolab-2fa-save', [$this, 'settings_save']);
            $this->register_action('plugin.kolab-2fa-verify', [$this, 'settings_verify']);
        }

        return $args;
    }

    /**
     * Handler for the additional login step requesting the 2FA verification code
     */
    public function login_step(): void
    {
        // replace handler for login form
        $this->api->output->add_handler('loginform', [$this, 'auth_form']);

        // focus the code input field on load
        $this->api->output->add_script('$("input.kolab2facode").first().select();document.querySelector("body").className=document.querySelector("body").className.replace(/^task-.*? /,"task-login ")', 'docready');
        $this->api->output->add_header('<style>#login-form table tr:not(:first-child)::before { content: \'' . $this->gettext('or') . '\'; text-align:center; width: 100%}</style>');
        $this->api->output->set_env('task', 'login');

        $this->api->output->send('login');
    }

    /**
     * Process the 2nd factor code verification form submission
     * @throws Exception
     */
    public function login_verify($args)
    {
        $_SESSION['kolab_2fa_login_verified'] = false;

        $rcmail = rcmail::get_instance();

        $time = $_SESSION['kolab_2fa_time'];
        $nonce = $_SESSION['kolab_2fa_nonce'];
        $factors = $this->get_factors();
        $expired = $time < time() - $rcmail->config->get('kolab_2fa_timeout', 120);
        $username = !empty($_SESSION['kolab_auth_admin']) ? $_SESSION['kolab_auth_admin'] : $_SESSION['username'];

        $used_factor = null;

        if (!empty($factors) && !empty($nonce) && !$expired) {
            // TODO: check signature

            // try to verify each configured factor
            foreach ($factors as $factor) {
                [$method] = explode(':', $factor, 2);

                // verify the submitted code
                $code = rcube_utils::get_input_value("_{$nonce}_$method", rcube_utils::INPUT_POST);
                $_SESSION['kolab_2fa_login_verified'] = $this->verify_factor_auth($factor, $code, $username);

                // accept first successful method
                if ($_SESSION['kolab_2fa_login_verified']) {
                    $used_factor = $factor;
                    break;
                }
            }
        }

        if (!$_SESSION['kolab_2fa_login_verified']) {
            $rcmail->output->show_message('loginfailed', 'warning');
            $rcmail->kill_session();
//            $rcmail->output->redirect(['task' => 'login']);
            header('HTTP/1.0 401 Unauthorized');
            return ['task' => 'login'];
        }

        $rcmail->session->remove('temp');
        $rcmail->session->remove('kolab_2fa_time');
        $rcmail->session->remove('kolab_2fa_nonce');
        $rcmail->session->regenerate_id(false);

        // send auth cookie if necessary
        $rcmail->session->set_auth_cookie();

        $this->log_2fa($used_factor);

        self::log($args);

        if ($url = rcube_utils::get_input_string('_url', rcube_utils::INPUT_POST)) {
            parse_str($url, $query);

            return array_combine(
                array_map(fn ($k)=>trim($k,"_"), array_keys($query)),
                array_values($query));
        } else {
            return $args + ['task' => 'mail'];
        }
    }

    /**
     * Helper method to verify the given method/code tuple
     * @throws Exception
     */
    protected function verify_factor_auth($method, $code, $username): bool
    {
        if (strlen($code) && ($driver = $this->get_driver($method, $username))) {
            try {
                // verify the submitted code
                return $driver->verify($code, $_SESSION['kolab_2fa_time']);
            } catch (Exception $e) {
                rcube::raise_error($e, true);
            }
        }

        return false;
    }

    /**
     * Render 2nd factor authentication form in place of the regular login form
     * @throws Exception
     */
    public function auth_form($attrib = [], $is_login = true)
    {
        $form_name = !empty($attrib['form']) ? $attrib['form'] : 'form';
        $nonce = $_SESSION['kolab_2fa_nonce'];

        $methods = array_unique(array_map(
            function ($factor) {
                [$method,] = explode(':', $factor);
                return $method;
            },
            $this->get_factors()
        ));

        if ($is_login) {
            // forward these values as the regular login screen would submit them
            $input_task = new html_hiddenfield(['name' => '_task', 'value' => 'login']);
            $input_action = new html_hiddenfield(['name' => '_action', 'value' => 'plugin.kolab-2fa-login']);
            // save original url
            $url = rcube_utils::get_input_string('_url', rcube_utils::INPUT_POST);

            if (
                empty($url)
                && !empty($_SERVER['QUERY_STRING'])
                && !preg_match('/_(task|action)=logout/', $_SERVER['QUERY_STRING'])
            ) {
                $url = $_SERVER['QUERY_STRING'];
            }
            $input_url = new html_hiddenfield(['name' => '_url', 'id' => 'rcmloginurl', 'value' => $url]);
        }
        // create HTML table with two cols
        $table = new html_table(['cols' => 2, 'class' => 'w-100']);
        $required = count($methods) > 1 ? null : 'required';

        // render input for each configured auth method
        foreach ($methods as $method) {

            $field_id = "rcmlogin2fa$method";

            $input_code = $this->get_driver($method)->login_input("_{$nonce}_$method", $field_id, $attrib, $required);

            $table->add(['class' => 'title'], html::label($field_id, html::quote($this->gettext($method))));
            $table->add(['class' => 'input'], $input_code ? $input_code->show('') : "");
        }


        if($is_login) {
            $out = $input_task->show();
            $out .= $input_action->show();
            $out .= $input_url->show();
        } else {
            $out = "";
        }
        $out .= $table->show();

        // add submit button
        if (rcube_utils::get_boolean($attrib['submit'] ?? false)) {
            $out .= html::p(
                'formbuttons',
                html::tag('button', [
                    'type' => 'submit',
                    'id' => 'rcmloginsubmit',
                    'class' => 'button mainaction save',
                ], $this->gettext('continue'))
            );
        }

        // surround html output with a form tag
        if (empty($attrib['form'])) {
            $out = $this->api->output->form_tag(['name' => $form_name, 'method' => 'post'], $out);
        }

        return $out;
    }

    /**
     * Load driver class for the given authentication factor
     *
     * @param string $factor Factor identifier (<method>:<id>)
     * @param string|null $username Username (email)
     *
     * @return Kolab2FA\Driver\DriverBase|false
     * @throws Exception
     */
    public function get_driver(string $factor, ?string $username = null): DriverBase|false
    {
        [$method] = explode(':', $factor, 2);

        $rcmail = rcmail::get_instance();

        if (!empty($this->drivers[$factor])) {
            return $this->drivers[$factor];
        }

        $config = $rcmail->config->get('kolab_2fa_' . $method, []);

        // use product name as "issuer"
        if (empty($config['issuer'])) {
            $config['issuer'] = $rcmail->config->get('product_name');
        }

        if (empty($username) && $rcmail->user->ID) {
            $username = $rcmail->get_user_name();
        }

        try {

            $storage = $this->get_storage($username);

            $driver = DriverBase::factory($storage, $factor, $config, $this);

            $this->drivers[$factor] = $driver;
            return $driver;
        } catch (Exception $e) {
            $error = strval($e);
        }

        rcube::raise_error(
            [
                'code' => 600,
                'type' => 'php',
                'file' => __FILE__,
                'line' => __LINE__,
                'message' => $error],
            true
        );

        return false;
    }

    /**
     * Getter for a storage instance singleton
     * @throws Exception
     */
    public function get_storage($for = null)
    {
        if (!isset($this->storage) || (!empty($for) && $this->storage->username !== $for)) {
            $rcmail = rcmail::get_instance();
            try {
                $this->storage = StorageBase::factory(
                    $rcmail->config->get('kolab_2fa_storage', 'roundcube'),
                    $rcmail->config->get('kolab_2fa_storage_config', [])
                );

                $this->storage->set_username($for);
                $this->storage->set_logger(new RcubeLogger());

                // set user properties from active session
                if (!empty($_SESSION['kolab_dn'])) {
                    $this->storage->userdn = $_SESSION['kolab_dn'];
                }
            } catch (Exception $e) {
                $this->storage = null;

                rcube::raise_error(
                    [
                        'code' => 600,
                        'type' => 'php',
                        'file' => __FILE__,
                        'line' => __LINE__,
                        'message' => $e->getMessage()],
                    true
                );
            }
        }

        return $this->storage;
    }

    /**
     * Handler for 'settings_actions' hook
     */
    public function settings_actions($args): array
    {
        // register as settings action
        $args['actions'][] = [
            'action' => 'plugin.kolab-2fa',
            'class' => 'twofactorauth',
            'label' => 'settingslist',
            'title' => 'settingstitle',
            'domain' => 'kolab_2fa',
        ];

        return $args;
    }

    /**
     * Handler for settings/plugin.kolab-2fa requests
     */
    public function settings_view(): void
    {
        $this->register_handler('plugin.settingsform', [$this, 'settings_form']);
        $this->register_handler('plugin.settingslist', [$this, 'settings_list']);
        $this->register_handler('plugin.factoradder', [$this, 'settings_factoradder']);
        $this->register_handler('plugin.factorinfo', [$this, 'settings_factorinfo']);
        $this->register_handler('plugin.highsecuritydialogform', [$this, 'settings_highsecuritydialog']);

        $this->include_script('kolab2fa.js');
        $this->include_stylesheet($this->local_skin_path() . '/kolab2fa.css');

        $this->api->output->set_env('session_secured', $this->check_secure_mode());
        $this->api->output->add_label('save', 'cancel');
        $this->api->output->set_pagetitle($this->gettext('settingstitle'));
        $this->api->output->send('kolab_2fa.config');
    }

    /**
     * Render the menu to add another authentication factor
     */
    public function settings_factoradder($attrib): string
    {
        $rcmail = rcmail::get_instance();

        $attrib['id'] = 'kolab2fa-add';

        $select = new html_select($attrib);
        $select->add($this->gettext('addfactor') . '...', '');
        foreach ((array)$rcmail->config->get('kolab_2fa_drivers', []) as $method) {
            $select->add($this->gettext($method), $method);
        }

        return $select->show();
    }

    /**
     * Render an info box if the user was force redirected to set up a secound factor
     * @param $attrib
     * @return string
     */
    public function settings_factorinfo($attrib): string
    {
        $attrib['id'] = 'kolab2fa-info';

        $force = $_SESSION['kolab_2fa_setup_forced'];
        unset($_SESSION['kolab_2fa_setup_forced']);

        return $force ?
            html::p($attrib, $this->gettext('factorforcedinfo')) :
            "";
    }

    /**
     * Render a list of active factor this user has configured
     */
    public function settings_list($attrib = []): string
    {
        $attrib['id'] = 'kolab2fa-factors';
        $table = new html_table(['cols' => 3]);

        $table->add_header('name', $this->gettext('factor'));
        $table->add_header('created', $this->gettext('created'));
        $table->add_header('actions', '');

        return $table->show($attrib);
    }

    /**
     * Render the settings form template object
     * @throws Exception
     */
    public function settings_form($attrib = []): string
    {
        $rcmail = rcmail::get_instance();
        $factors = $this->get_factors();
        $drivers = (array)$rcmail->config->get('kolab_2fa_drivers', []);
        $out = '';
        $env_methods = [];

        foreach ($drivers as $method) {
            $out .= $this->settings_factor($method, $attrib);
            $env_methods[$method] = [
                'name' => $this->gettext($method),
                'active' => 0,
            ];
        }

        $me = $this;
        $factors = array_combine(
            $factors,
            array_map(function ($id) use ($me, &$env_methods) {
                $props = ['id' => $id];

                if ($driver = $me->get_driver($id)) {
                    $props += $this->format_props($driver->props());
                    $props['method'] = $driver->method;
                    $props['name'] = $me->gettext($driver->method);
                    $env_methods[$driver->method]['active']++;
                }

                return $props;
            }, $factors)
        );

        $this->api->output->set_env('kolab_2fa_methods', $env_methods);
        $this->api->output->set_env('kolab_2fa_factors', !empty($factors) ? $factors : null);

        return html::div(['id' => 'kolab2fapropform'], $out);
    }

    /**
     * Render the settings UI for the given method/driver
     * @throws Exception
     */
    protected function settings_factor($method, $attrib): string
    {
        $out = '';
        $rcmail = rcmail::get_instance();
        $attrib += ['class' => 'propform'];

        if ($driver = $this->get_driver($method)) {
            $table = new html_table(['cols' => 2, 'class' => $attrib['class']]);

            foreach ($driver->props() as $field => $prop) {
                if (!$prop['editable']) {
                    continue;
                }

                switch ($prop['type']) {
                    case 'boolean':
                    case 'checkbox':
                        $input = new html_checkbox(['value' => '1']);
                        break;

                    case 'enum':
                    case 'select':
                        $input = new html_select(['disabled' => !empty($prop['readonly'])]);
                        $input->add(array_map([$this, 'gettext'], $prop['options']), $prop['options']);
                        break;

                    default:
                        $input = new html_inputfield([
                            'size' => !empty($prop['size']) ? $prop['size'] : 30,
                            'disabled' => empty($prop['editable']),
                        ]);
                }

                $explain_label = $field . 'explain' . $method;
                $explain_html = $rcmail->text_exists($explain_label, 'kolab_2fa') ? html::div('explain form-text', $this->gettext($explain_label)) : '';

                $field_id = 'rcmk2fa' . $method . $field;
                $table->add(['class' => 'title'], html::label($field_id, $this->gettext($field)));
                $table->add([], $input->show('', ['id' => $field_id, 'name' => "_prop[$field]"]) . $explain_html);
            }

            // add row for displaying the QR code
            if (method_exists($driver, 'get_provisioning_uri')) {
                $gif = 'data:image/gif;base64,R0lGODlhDwAPAIAAAMDAwAAAACH5BAEAAAAALAAAAAAPAA8AQAINhI+py+0Po5y02otnAQA7';
                $table->add(['class' => 'title'], $this->gettext('qrcode'));
                $table->add(
                    ['class' => 'pl-3 pr-3'],
                    html::div('explain form-text', $this->gettext("qrcodeexplain$method"))
                    . html::tag('img', ['src' => $gif, 'class' => 'qrcode mt-2', 'rel' => $method])
                );

                // add row for testing the factor
                $field_id = 'rcmk2faverify' . $method;
                $table->add(['class' => 'title'], html::label($field_id, $this->gettext('verifycode')));
                $table->add(
                    [],
                    html::tag('input', ['type' => 'text', 'name' => '_verify_code', 'id' => $field_id, 'class' => 'k2fa-verify', 'size' => 20, 'required' => true]) .
                    html::div('explain form-text', $this->gettext("verifycodeexplain$method"))
                );
            }

            $input_id = new html_hiddenfield(['name' => '_prop[id]', 'value' => '']);

            $out .= html::tag(
                'form',
                [
                    'method' => 'post',
                    'action' => '#',
                    'id' => 'kolab2fa-prop-' . $method,
                    'style' => 'display:none',
                    'class' => 'propform',
                ],
                html::tag(
                    'fieldset',
                    [],
                    html::tag('legend', [], $this->gettext($method)) .
                    html::div('factorprop', $table->show()) .
                    $input_id->show()
                )
            );
        }

        return $out;
    }

    /**
     * Render the high-security-dialog content
     * @throws Exception
     */
    public function settings_highsecuritydialog($attrib = [])
    {
//        $attrib += ['id' => 'kolab2fa-highsecuritydialog'];
//
//        $field_id = 'rcmk2facode';
//        $input = new html_inputfield(['name' => '_code', 'id' => $field_id, 'class' => 'verifycode', 'size' => 20]);
//        $label = html::label(['for' => $field_id, 'class' => 'col-form-label col-sm-4'], '$name');
//
//        return html::div(
//            $attrib,
//            html::div('explain form-text', $this->gettext('highsecuritydialog'))
//            . html::div('propform row form-group', $label . html::div('col-sm-8', $input->show('')))
//        );
        $_SESSION['kolab_2fa_time'] = time();
        $_SESSION['kolab_2fa_nonce'] = bin2hex(openssl_random_pseudo_bytes(32));

        $this->api->output->add_header('<style>#highsec-form table tr:not(:first-child)::before { content: \'' . $this->gettext('or') . '\'; text-align:center; width: 100%}</style>');

        return $this->auth_form($attrib, false);
    }

    /**
     * Handler for settings/plugin.kolab-2fa-save requests
     * @throws Exception
     */
    public function settings_save(): void
    {
        $method = rcube_utils::get_input_value('_method', rcube_utils::INPUT_POST);
        $data = @json_decode(rcube_utils::get_input_value('_data', rcube_utils::INPUT_POST), true);

        //$rcmail = rcmail::get_instance();
        //$storage = $this->get_storage($rcmail->get_user_name());
        $success = false;
        $errors = 0;
        $save_data = [];

        if ($driver = $this->get_driver($method)) {
            if ($data === false) {
                if ($this->check_secure_mode()) {
                    // remove method from active factors and clear stored settings
                    $success = $driver->clear();
                } else {
                    $errors++;
                }
            } else {
                // verify the submitted code before saving
                $verify_code = rcube_utils::get_input_value('_verify_code', rcube_utils::INPUT_POST);
                $timestamp = intval(rcube_utils::get_input_value('_timestamp', rcube_utils::INPUT_POST));
                if (!empty($verify_code)) {
                    if (!$driver->verify($verify_code, $timestamp)) {
                        $this->api->output->command('plugin.verify_response', [
                            'id' => $driver->id,
                            'method' => $driver->method,
                            'success' => false,
                            'message' => str_replace('$method', $this->gettext($driver->method), $this->gettext('codeverificationfailed')),
                        ]);
                        $this->api->output->send();
                    }
                }

                foreach ($data as $prop => $value) {
                    if (!$driver->set($prop, $value)) {
                        $errors++;
                    }
                }

                $driver->set('active', true);
            }

            // commit changes to the user properties
            if (!$errors) {
                if ($success = $driver->commit()) {
                    $save_data = $data !== false ? $this->format_props($driver->props()) : [];
                } else {
                    $errors++;
                }
            }
        }

        if ($success) {
            $this->api->output->show_message($data === false ? $this->gettext('factorremovesuccess') : $this->gettext('factorsavesuccess'), 'confirmation');
            $this->api->output->command('plugin.save_success', [
                    'method' => $method,
                    'active' => $data !== false,
                    'id' => $driver->id] + $save_data);
        } elseif ($errors) {
            $this->api->output->show_message($this->gettext('factorsaveerror'), 'error');
            $this->api->output->command('plugin.reset_form', $data !== false ? $method : null);
        }

        $this->api->output->send();
    }

    /**
     * Handler for settings/plugin.kolab-2fa-data requests
     * @throws Exception
     */
    public function settings_data(): void
    {
        $method = rcube_utils::get_input_value('_method', rcube_utils::INPUT_POST);

        if ($driver = $this->get_driver($method)) {
            $data = ['method' => $method, 'id' => $driver->id];

            foreach ($driver->props(true) as $field => $prop) {
                $data[$field] = $prop['text'] ?: $prop['value'];
            }

            // generate QR code for provisioning URI
            if (method_exists($driver, 'get_provisioning_uri')) {
                try {
                    $uri = $driver->get_provisioning_uri();

                    // Some OTP apps have an issue with algorithm character case
                    // So we make sure we use upper-case per the spec.
                    $uri = str_replace('algorithm=sha', 'algorithm=SHA', $uri);

                    $qr = new Endroid\QrCode\QrCode();
                    $qr->setText($uri)
                        ->setSize(240)
                        ->setPadding(10)
                        ->setErrorCorrection('high')
                        ->setForegroundColor(['r' => 0, 'g' => 0, 'b' => 0, 'a' => 0])
                        ->setBackgroundColor(['r' => 255, 'g' => 255, 'b' => 255, 'a' => 0]);
                    $data['qrcode'] = base64_encode($qr->get());
                } catch (Exception $e) {
                    rcube::raise_error($e, true);
                }
            }

            $this->api->output->command('plugin.render_data', $data);
        }

        $this->api->output->send();
    }

    /**
     * Handler for settings/plugin.kolab-2fa-verify requests
     * @throws Exception
     */
    public function settings_verify(): void
    {
//        $method = rcube_utils::get_input_value('_method', rcube_utils::INPUT_POST);
//        $timestamp = intval(rcube_utils::get_input_value('_timestamp', rcube_utils::INPUT_POST));
        $success = false;

        $rcmail = rcmail::get_instance();

        $time = $_SESSION['kolab_2fa_time'];
        $nonce = $_SESSION['kolab_2fa_nonce'];
        $factors = $this->get_factors();
        $expired = $time < time() - $rcmail->config->get('kolab_2fa_timeout', 120);
        $username = !empty($_SESSION['kolab_auth_admin']) ? $_SESSION['kolab_auth_admin'] : $_SESSION['username'];

        $used_factor = null;

        if (!empty($factors) && !empty($nonce) && !$expired) {
            // TODO: check signature
            // TODO: which signature??

            // try to verify each configured factor
            foreach ($factors as $factor) {
                [$method] = explode(':', $factor, 2);
                // verify the submitted code
                $code = rcube_utils::get_input_value("_{$nonce}_$method", rcube_utils::INPUT_POST);
                $success = $this->verify_factor_auth($factor, $code, $username);

                // accept first successful method
                if ($success) {
                    $used_factor = $factor;
                    error_log("settings verify iter success");
                    break;
                } else {
                    error_log("settings verify iter fail");
                }
            }
        }

        // put session into high-security mode
        if ($success && !empty($_POST['_session'])) {
            $_SESSION['kolab_2fa_secure_mode'] = time();
        }

        if ($expired) {
            rcube::raise_error([
                'code' => 701,
                'message' => $this->gettext('loginexpired')
            ], true, true);
        }

        if (!empty($used_factor)) {
            [$method] = explode(':', $used_factor, 2);
        } else {
            $method = null;
        }

        $this->api->output->command('plugin.verify_response', [
            'method' => $method,
            'success' => $success,
            'message' => str_replace(
                '$method',
                $this->gettext($method),
                $this->gettext($success ? 'codeverificationpassed' : 'codeverificationfailed')
            ),
        ]);

        $this->api->output->send();
    }

    /**
     *
     */
    protected function format_props($props): array
    {
        $rcmail = rcmail::get_instance();
        $values = [];

        foreach ($props as $key => $prop) {
            $value = match ($prop['type']) {
                'datetime' => $rcmail->format_date($prop['value']),
                default => $prop['value'],
            };

            $values[$key] = $value;
        }

        return $values;
    }

    /**
     * Check whether the session is secured with 2FA (excluding the logon)
     */
    protected function check_secure_mode()
    {
        // Allow admins that used kolab_auth's "login as" feature to act without
        // being asked for the user's second factor
        if (!empty($_SESSION['kolab_auth_admin']) && !empty($_SESSION['kolab_auth_password'])) {
            return true;
        }

        if (!empty($_SESSION['kolab_2fa_secure_mode']) && $_SESSION['kolab_2fa_secure_mode'] > time() - 180) {
            return $_SESSION['kolab_2fa_secure_mode'];
        }

        return false;
    }

    private function log_2fa($used_factor, $user = null, $failed_login = false, $error_code = 0): void
    {
        $rcmail = rcmail::get_instance();

        if (!$rcmail->config->get('log_logins')) {
            return;
        }

        // don't log full session id for security reasons
        $session_id = session_id();
        $session_id = $session_id ? substr($session_id, 0, 16) : 'no-session';

        // failed login
        if ($failed_login) {
            // don't fill the log with complete input, which could
            // have been prepared by a hacker
            if (strlen($user) > 256) {
                $user = substr($user, 0, 256) . '...';
            }

            $message = sprintf('Failed 2fa for %s from %s in session %s (error: %d)',
                $user, rcube_utils::remote_ip(), $session_id, $error_code);
        }
        // successful login
        else {
            $user_name = $rcmail->get_user_name();
            $user_id   = $rcmail->get_user_id();

            if (!$user_id) {
                return;
            }

            $message = sprintf('Successful 2fa for %s (ID: %d) from %s in session %s, using %s',
                $user_name, $user_id, rcube_utils::remote_ip(), $session_id, $used_factor);
        }

        // log login
        rcmail::write_log('userlogins', $message);
    }
}
