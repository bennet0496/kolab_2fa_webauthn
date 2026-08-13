/*
 * Copyright (c) 2026 Bennet Becker <dev@bennet.cc>
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


document.addEventListener("readystatechange", function () {
    if (document.readyState === "complete") {
        let className = document.querySelector("body").className;
        document.querySelector("body").className = className.replace(/^task-.*? /, "task-login ");

        $("input.kolab2facode").first().select();

        $("#rcmlogin2faother").click(
            (ev) => {
                document.querySelectorAll(".rcmlogin2famethodrow").forEach(r => r.classList.add("hidden"));
                document.querySelectorAll(".rcmlogin2famethodchooserrow, .rcmlogin2famethoddirect").forEach(r => r.classList.remove("hidden"));
                ev.target.classList.add("hidden");
            }
        )

        $(".rcmlogin2famethodchooserrow button").click(function (ev){
           console.log(ev);
           const method = ev.target.value;
           document.querySelectorAll(".rcmlogin2famethodchooserrow, .rcmlogin2famethodrow").forEach((r) => {
               console.log(r)
               r.classList.add("hidden");
           });

           document.querySelector(".rcmlogin2famethod" + method)?.classList.remove("hidden");
           document.querySelector("#rcmlogin2faother").classList.remove("hidden");
        });

        document.querySelectorAll("input.kolab2facode").forEach((ipb) => {
            const appendSpan = document.createElement("span");
            appendSpan.className = "input-group-append";

            const submitButton = document.createElement("button");
            submitButton.type = "submit";
            submitButton.innerHTML = "<i class=\"icon right\"></i>";
            submitButton.className = "input-group-text px-0"

            appendSpan.appendChild(submitButton);

            ipb.insertAdjacentElement("afterend", appendSpan);
        })

        document.querySelectorAll(".rcmlogin2famethodchooserrow span.input-group-prepend").forEach(e => e.parentElement.removeChild(e))
        document.querySelectorAll(".rcmlogin2famethodchooserrow input[type=hidden]").forEach(e => e.parentElement.removeChild(e))

        $("input.kolab2facode").keypress((evt) => {
            console.log(evt);
        })

        $("#rcmlogin2facancel").click(function(e) {
            rcmail.http_post('plugin.kolab-2fa-login-cancel')
        })
    }
})