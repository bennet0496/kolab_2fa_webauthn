/**
 * Kolab 2-Factor-Authentication plugin client functions
 *
 * @author Thomas Bruederli <bruederli@kolabsys.com>
 *
 * @licstart  The following is the entire license notice for the
 * JavaScript code in this page.
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
 *
 * @licend  The above is the entire license notice
 * for the JavaScript code in this page.
 */

window.rcmail && rcmail.addEventListener('init', function() {
    /**
     *
     * @type {function[]}
     */
    const highsec_call_stack = [];
    /**
     * @var {any|jQuery|HTMLElement}
     */
    let highsec_dialog;
    /**
     * @var {any|jQuery|HTMLElement}
     */
    let factor_dialog;

    if (!rcmail.env.kolab_2fa_factors) {
        rcmail.env.kolab_2fa_factors = {};
    }

    /**
     * Equivalend of PHP time()
     */
    function time() {
        return Math.round(new Date().getTime() / 1000);
    }

    /**
     * Open dialog to add the given authentication factor
     */
    function add_factor(method) {
        // noinspection JSUnusedLocalSymbols
        let lock;
        /**
         * @type {Node}
         */
        const formTemplate = document.querySelector('#kolab2fa-template-' + method)
            .content.cloneNode(true);

        rcmail.triggerEvent('kolab2fa_add_factor', { method: method });

        factor_dialog = rcmail.show_popup_dialog(
            formTemplate,
            rcmail.get_label('addfactor', 'kolab_2fa'),
            [
                {
                    text: rcmail.gettext('save', 'kolab_2fa'),
                    'class': 'mainaction save',
                    click: function() {
                        save_data(method);
                    }
                },
                {
                    text: rcmail.gettext('cancel'),
                    'class': 'cancel',
                    click: function() {
                        factor_dialog.dialog('destroy');
                        window.location.reload();
                    }
                }
            ],
            {
                open: function(event) {
                    event.target.querySelector('input[name="_verify_code"]')?.addEventListener('keydown',
                        /**
                         * @param {KeyboardEvent} e
                         */
                        function(e) {
                        if (e.key === 'Enter') {
                            e.target.closest('.ui-dialog').querySelector('button.mainaction').click();
                        }
                    });
                },
                close: function() {
                    formTemplate.parentNode?.removeChild(formTemplate);
                    factor_dialog.dialog('destroy');
                },
                height: (method === "totp" || method === "htop") ? 500 : 160
            }
        )
        .data('method', method);

        console.log(formTemplate);
        document.querySelector("form.propform").addEventListener('submit', function(sevent) {
            save_data(method);
            sevent.preventDefault();
            return false;
        });

        // load generated data
        lock = rcmail.set_busy(true, 'loading');
        rcmail.http_post('plugin.kolab-2fa-data', { _method: method }, lock);
    }

    /**
     * Remove the given factor from the account
     */
    function remove_factor(id) {
        const lock = rcmail.set_busy(true, 'saving');
        rcmail.http_post('plugin.kolab-2fa-save', { _method: id, _data: 'false' }, lock);
    }

    /**
     * Submit factor settings form
     */
    function save_data(method) {
        const form = document.querySelector('#kolab2fa-prop-' + method);
        const verify = form?.querySelector('input[name="_verify_code"]');

        if (verify !== null && !verify.value.length) {
            alert(rcmail.get_label('verifycodemissing','kolab_2fa'));
            verify.select();
            return false;
        }

        const data = form_data(form);
        const lock = rcmail.set_busy(true, 'saving');
        rcmail.http_post('plugin.kolab-2fa-save', {
            _method: data.id || method,
            _data: JSON.stringify(data),
            _verify_code: verify?.value,
        }, lock);
    }

    /**
     * Collect all factor properties from the form
     *
     * @param {HTMLFormElement} form
     */
    function form_data(form)
    {
        const data = {};
        form.querySelectorAll('input, select')
            .forEach(function(elem) {
                console.log(elem);
                if (elem.name.startsWith('_+prop')) {
                    console.log("prop")
                    const k = elem.name.match(/\[([a-z0-9_.-]+)]$/i); //? RegExp.$1 : null;
                    if (k?.length > 1) {
                        console.log(k)
                        data[k[1]] = elem.tagName === 'SELECT' ?
                            elem.querySelector('option:selected')?.value : elem.value;
                    }
                }
        });

        return data;
    }

    /**
     * Execute the given function after the user authorized the session with a 2nd factor
     */
    function require_high_security(func, exclude)
    {
        // request 2nd factor auth
        if (rcmail.env.session_secured !== true && rcmail.env.session_secured < time() - 180) {
            let method, name;

            // find an active factor
            $.each(rcmail.env.kolab_2fa_factors, function(id, prop) {
                if (prop.active && !method || method === exclude) {
                    method = id;
                    name = prop.label || prop.name;
                    if (!exclude || id !== exclude) {
                        return true;
                    }
                }
            });

            // we have a registered factor, use it
            if (method) {
                highsec_call_stack.push(func);

                // TODO: list all active factors to choose from
                // var html = String($('#kolab2fa-highsecuritydialog').html()).replace('$name', name);
                const template = document.querySelector('#kolab2fa-template-highsecuritydialog');

                highsec_dialog = rcmail.show_popup_dialog(
                    template.content.cloneNode(true),
                    rcmail.get_label('highsecurityrequired', 'kolab_2fa'),
                    [
                        {
                            text: rcmail.gettext('enterhighsecurity', 'kolab_2fa'),
                            click: function(e) {
                                console.log("submit highsec form from button:", e, e.target);
                                document.querySelector('#highsec-form').requestSubmit();
                            },
                            'class': 'mainaction save'
                        },
                        {
                            text: rcmail.gettext('choose_other', 'kolab_2fa'),
                            click: function(e) {
                                document.querySelectorAll(".rcmlogin2famethodrow").forEach(r => r.classList.add("hidden"));
                                document.querySelectorAll(".rcmlogin2famethodchooserrow, .rcmlogin2famethoddirect").forEach(r => r.classList.remove("hidden"));
                            },
                            'class': ''
                        },
                        {
                            text: rcmail.gettext('cancel'),
                            'class': 'cancel btn-danger',
                            click: function() {
                                highsec_dialog.dialog('destory');
                                window.location.reload();
                            }
                        }
                    ],
                    {
                        open: function(event, ui) {
                            // submit code on <Enter>
                            console.log("opening highsec form ", event, ui);

                            $(event.target).find('form table tr').each(function() {
                                const input = $('input,select', this),
                                    label = $('label', this),
                                    icon_name = input.data('icon'),
                                    icon = $('<i>').attr('class', 'input-group-text icon ' + input.attr('name').replace('_', ''));

                                if (icon_name) {
                                    icon.addClass(icon_name);
                                }

                                $(this).addClass('form-group row');
                                label.parent().css('display', 'none');
                                input.addClass(input.is('select') ? 'custom-select' : 'form-control')
                                    .attr('placeholder', label.text())
                                    .keypress(function(e) {
                                        if (e.which === 13) {
                                            console.log("submit highsec form from enter-key", e, e.target);
                                            document.querySelector('#highsec-form').requestSubmit();
                                        }
                                    })
                                    .before($('<span class="input-group-prepend">').append(icon))
                                    .parent().addClass('input-group input-group-lg');
                            });

                            rcmail.triggerEvent('kolab2fa_style_elements', { form: $("#highsec-form") });
                            document.querySelectorAll(".rcmlogin2famethodchooserrow span.input-group-prepend").forEach(e => e.parentElement.removeChild(e))
                            document.querySelectorAll(".rcmlogin2famethodchooserrow input[type=hidden]").forEach(e => e.parentElement.removeChild(e))

                            $(".rcmlogin2famethodchooserrow button").click(function (ev){
                                console.log(ev);
                                const method = ev.target.value;
                                document.querySelectorAll(".rcmlogin2famethodchooserrow, .rcmlogin2famethodrow").forEach((r) => {
                                    console.log(r)
                                    r.classList.add("hidden");
                                });

                                document.querySelector(".rcmlogin2famethod" + method)?.classList.remove("hidden");
                                document.querySelector("#rcmlogin2faother")?.classList.remove("hidden");
                            });

                            //$("#highsec-form").on('submit',
                            document.querySelector('#highsec-form').addEventListener('submit', function(e) {
                                e.preventDefault();
                                console.log("#highsec-form submit", e);
                                let formData = Array.from(e.currentTarget.elements).reduce(function(a, b) {
                                    if (!["_task", "_action"].includes(b.name))
                                        a[b.name] = b.value;
                                    return a;
                                }, {});

                                console.log(formData);

                                let lock = rcmail.set_busy(true, 'verifying');

                                rcmail.http_post('plugin.kolab-2fa-verify', {
                                    ...formData,
                                    _session: 1,
                                    _timestamp: highsec_dialog.data('timestamp')
                                }, lock);

                                return false;
                            });

                            $(event.target).closest('input.kolab2facode').keypress(function(e) {
                                if (e.which === 13) {
                                    $(e.target).closest('.ui-dialog').find('button.mainaction').click();
                                }
                            }).select();
                        },
                        close: function() {
                            $(this).remove();
                            highsec_dialog = null;
                            highsec_call_stack.pop();
                        }
                    }
                ).data('timestamp', time());

                return false;
            }
        }

        // just trigger the callback
        func.call(this);
    }

    /**
     * @var
     */
    const {startRegistration, startAuthentication} = SimpleWebAuthnBrowser;

    /**
     *
     * @param {*} data
     * @param {HTMLElement} form
     */
    function render_data(data, form) {
        if (data.method === 'webauthn') {
            // const data = await rcmail.http_get('plugin.kolab-2fa-webauthn-gro', {})
            const optionsJSON = JSON.parse(data.registration_options);

            startRegistration({optionsJSON}).then(attResp => {
                console.log(attResp);
                let responseElement = document.createElement("input");
                responseElement.type = "hidden";
                responseElement.name = "_prop[creation_response]";
                responseElement.value = JSON.stringify(attResp);

                form.appendChild(responseElement);
            }).catch(error => {
                console.log(error);

                const span = document.createElement("span");
                span.style.textAlign = "left";
                span.innerText = error;

                document.querySelector(".ui-dialog-content")
                    .replaceChildren(span);

                document.querySelector(".mainaction").remove();
            });
        } else if (data.method === 'backupcodes') {
            /**
             * @var {number} code
             */
            for (let code in data.codes) {
                const span = document.createElement("span");
                span.style.textAlign = "left";
                span.innerText = data.codes[code];
                span.style.fontFamily = 'monospace, "Roboto Mono", "Ubuntu Mono"';
                span.style.marginInlineEnd = "1em";
                span.style.display = "inline-block";

                form.append(span, document.createElement("br"));
            }
        }
    }

    // callback for factor data provided by the server
    rcmail.addEventListener('plugin.render_data', function(data) {
        /**
         * @var {string} method
         */
        const method = data.method;
        const form = document.querySelector('#kolab2fa-prop-' + method);

        if (form === null) {
            console.error("Cannot assign auth data", data);
            return;
        }

        if (data.error) {
            form.innerText = data.error;
            return;
        }

        console.log(data);

        render_data(data, form);

        for (let dataKey in data) {
            const element = form.querySelector("[name=\"_prop[" + dataKey + "]\"]");
            if (element) {
                element.value = data[dataKey];
            }

            if (data.qrcode) {
                document.querySelector('img.qrcode[rel='+method+']').src = data.qrcode;
            }
        }
    });

    // callback for save action
    rcmail.addEventListener('plugin.save_success', function(data) {
        if (!data.active && rcmail.env.kolab_2fa_factors[data.id]) {
            delete rcmail.env.kolab_2fa_factors[data.id];
        }
        else if (rcmail.env.kolab_2fa_factors[data.id]) {
            $.extend(rcmail.env.kolab_2fa_factors[data.id], data);
        }
        else {
            rcmail.env.kolab_2fa_factors[data.id] = data;
        }

        if (factor_dialog) {
            factor_dialog.dialog('destroy');
        }

        // render();
        window.location.reload();
    });

    // callback for verify action
    rcmail.addEventListener('plugin.verify_response', function(data) {
        // execute high-security call stack and close dialog
        console.log(highsec_dialog)
        if (data.success && highsec_dialog && highsec_dialog.is(':visible')) {
            let func;
            while (highsec_call_stack.length) {
                func = highsec_call_stack.pop();
                func();
            }

            console.log("closing high sec form")
            highsec_dialog.dialog('destroy');
            rcmail.env.session_secured = time();
        }
        else {
            rcmail.display_message(data.message, data.success ? 'confirmation' : 'warning');

            if (highsec_dialog && highsec_dialog.is(':visible')) {
                highsec_dialog.find('input[name="_code"]').val('').select();
            }
            else {
                $('#kolab2fa-prop-' + data.method + ' input.k2fa-verify').val('').select();
            }
        }
    });

    // callback for save failure
    rcmail.addEventListener('plugin.reset_form', function(method) {
        if (method && rcmail.env.kolab_2fa_factors[method]) {
            rcmail.env.kolab_2fa_factors[method].active = false;
        }

        // render();
    });

    // handler for selections
    // needs to stay jquery other change event is not captureable in any way.
    $("#kolab2fa-add").change(function() {
        const method = this.value;

        // require auth verification
        require_high_security(function() {
            add_factor(method);
        });

        // noinspection JSUnusedGlobalSymbols
        this.selectedIndex = 0;
    });


    // handler for delete button clicks
    document.querySelectorAll("#kolab2fa-factors tbody .button.delete").forEach(function (element) {
        element.addEventListener('click', function () {
                const id = element.getAttribute("rel");

                // require auth verification
                require_high_security(function() {
                    if (confirm(rcmail.get_label('authremoveconfirm', 'kolab_2fa'))) {
                        remove_factor(id);
                    }
                }, id);

                return false;
        });
    })
});
