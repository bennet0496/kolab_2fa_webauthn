/*
 * Copyright (c) 2025 Bennet Becker <dev@bennet.cc>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

const {startRegistration, startAuthentication} = SimpleWebAuthnBrowser;


/**
 * @var rcmail rcube_webmail
 */

window.rcmail && rcmail.addEventListener('kolab2fa_render_data', async (event) => {
    console.log('kolab2fa_rander_data', event)
    if (event.data.method === 'webauthn') {
        // const data = await rcmail.http_get('plugin.kolab-2fa-webauthn-gro', {})
        const optionsJSON = JSON.parse(event?.data.registration_options);

        let attResp;
        try {
            // Pass the options to the authenticator and wait for a response
            attResp = await startRegistration({optionsJSON});
        } catch (error) {
            console.log(error)
        }

        console.log(attResp);
        if (event.form.length) {
            let responseElement = document.createElement("input");
            responseElement.type = "hidden";
            responseElement.name = "_prop[creation_response]";
            responseElement.value = JSON.stringify(attResp);

            event.form.get(0).appendChild(responseElement);
        }
    }
});

window.rcmail && rcmail.addEventListener('kolab2fa_style_elements', async (event) => {
    let name = $('#rcmlogin2fawebauthn').attr('name');
    let value = $('#rcmlogin2fawebauthn').attr('placeholder');
    let authopt = $('#rcmlogin2fawebauthn').attr('aria-auth-options');
    console.log(atob(authopt));
    $('#rcmlogin2fawebauthn').parent().html(
        `<button type="button"  
                class="kolab2facode button mainaction btn btn-primary form-control" id="rcmlogin2fawebauthnbutton" 
                aria-auth-options="${authopt}">${value}</button>
                <input type="hidden" name="${name}" id="rcmlogin2fawebauthn"/>`)
        .removeClass('input-group').addClass("w-100");

    $('#rcmlogin2fawebauthnbutton').click(async (cevent) => {
        const optionsJSON = JSON.parse(atob($(cevent.target).attr('aria-auth-options')));
        console.log(optionsJSON);

        let asseResp;
        try {
            // Pass the options to the authenticator and wait for a response
            asseResp = await startAuthentication({ optionsJSON });
        } catch (error) {
            console.log(error);
            $('#login-form').html(
                `<span style="text-align: left;">${error}</span><br/><a onclick="window.location.reload()" href="#">try again</a>`)
            return;
        }

        console.log(asseResp, event.form);
        document.querySelector('#rcmlogin2fawebauthn').value = JSON.stringify(asseResp);

        document.querySelector('#rcmlogin2fawebauthn').form.requestSubmit();

        // if (event.form.length) {
        //     document.querySelector("#" + event.form.get(0).id).submit();
        // }

    });
})

window.rcmail && rcmail.addEventListener('init', async () => {
    if (rcmail.env.task === 'login') {
        rcmail.triggerEvent('kolab2fa_style_elements', { form: $("#login-form") });
    }
});