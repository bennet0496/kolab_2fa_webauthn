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

const { startRegistration } = SimpleWebAuthnBrowser;


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
            attResp = await startRegistration({ optionsJSON });
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


// Start registration when the user clicks a button
// elemBegin.addEventListener('click', async () => {
//     // Reset success/error messages
//     elemSuccess.innerHTML = '';
//     elemError.innerHTML = '';
//
//     // GET registration options from the endpoint that calls
//     // @simplewebauthn/server -> generateRegistrationOptions()
//     const resp = await fetch('/generate-registration-options');
//     const optionsJSON = await resp.json();
//
//     let attResp;
//     try {
//         // Pass the options to the authenticator and wait for a response
//         attResp = await startRegistration({ optionsJSON });
//     } catch (error) {
//         // Some basic error handling
//         if (error.name === 'InvalidStateError') {
//             elemError.innerText = 'Error: Authenticator was probably already registered by user';
//         } else {
//             elemError.innerText = error;
//         }
//
//         throw error;
//     }
//
//     // POST the response to the endpoint that calls
//     // @simplewebauthn/server -> verifyRegistrationResponse()
//     const verificationResp = await fetch('/verify-registration', {
//         method: 'POST',
//         headers: {
//             'Content-Type': 'application/json',
//         },
//         body: JSON.stringify(attResp),
//     });
//
//     // Wait for the results of verification
//     const verificationJSON = await verificationResp.json();
//
//     // Show UI appropriate for the `verified` status
//     if (verificationJSON && verificationJSON.verified) {
//         elemSuccess.innerHTML = 'Success!';
//     } else {
//         elemError.innerHTML = `Oh no, something went wrong! Response: <pre>${JSON.stringify(
//             verificationJSON,
//         )}</pre>`;
//     }
// });