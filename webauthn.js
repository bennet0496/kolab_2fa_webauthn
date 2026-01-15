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
            console.log(error);

            const span = document.createElement("span");
            span.style.textAlign = "left";
            span.innerText = error;

            document.querySelector(".ui-dialog-content")
                .replaceChildren(span);

            document.querySelector(".mainaction").remove();

            return;
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
    const node = document.querySelector("#rcmlogin2fawebauthn");
    if (!node) return;

    const name = node.attributes.getNamedItem("name")?.value;
    const value = node.attributes.getNamedItem("placeholder")?.value;
    const authopt = node.attributes.getNamedItem("aria-auth-options")?.value;
    console.log(atob(authopt));

    const button = document.createElement("button");
    button.type = "button";
    button.className = "kolab2facode button mainaction btn btn-primary form-control";
    button.id = "rcmlogin2fawebauthnbutton";
    button.setAttribute("aria-auth-options", authopt);
    button.innerText = value;

    button.addEventListener("click", async (cevent) => {
        const aao = cevent.target.attributes.getNamedItem("aria-auth-options")?.value;
        const optionsJSON = JSON.parse(atob(aao));
        console.log(optionsJSON);

        let asseResp;
        try {
            // Pass the options to the authenticator and wait for a response
            asseResp = await startAuthentication({ optionsJSON });
        } catch (error) {
            console.log(error, error.name);

            const span = document.createElement("span");
            span.style.textAlign = "left";
            span.innerText = error;

            const again = document.createElement("a");
            again.innerText = rcmail.get_label('again', 'kolab_2fa');
            again.href = "#"
            again.style = {
                marginTop: "1.3rem",
                textDecoration: "underline",
                cursor: "pointer"
            }
            again.addEventListener("click", () => window.location.reload());

            document.querySelector("#login-form").replaceChildren(span, document.createElement("br"), again);
            return;
        }
        console.log(asseResp, event.form);

        document.querySelector('#rcmlogin2fawebauthn').value = JSON.stringify(asseResp);
        document.querySelector('#rcmlogin2fawebauthn').form.requestSubmit();
    });

    const input = document.createElement("input")
    input.type = "hidden";
    input.name = name;
    input.id = "rcmlogin2fawebauthn";

    node.parentElement.replaceChildren(button, input);

    if (!document.querySelector("#rcmlogin2fawebauthn").parentElement.classList.replace("input-group", "w-100")){
        document.querySelector("#rcmlogin2fawebauthn").parentElement.classList.add("w-100");
    }
})

window.rcmail && rcmail.addEventListener('init', async () => {
    if (rcmail.env.task === 'login') {
        rcmail.triggerEvent('kolab2fa_style_elements', { form: $("#login-form") });
    }
});