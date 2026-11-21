// Bastion front-end helpers. Loaded as an external file so it is allowed by the
// secure build's Content-Security-Policy (script-src 'self'; no inline scripts).
// Nothing here is a security control: every rule is enforced again on the server.
(function () {
  "use strict";

  // 1. Back button after logout. Some browsers restore pages from the
  //    back-forward cache without contacting the server. If an authenticated
  //    page is restored that way, reload it so the server decides (and
  //    redirects to sign-in if the session has ended).
  window.addEventListener("pageshow", function (event) {
    if (event.persisted && document.body.dataset.auth === "true") {
      window.location.reload();
    }
  });

  // 2. Live password checklist on the registration page. The patterns come
  //    from passwords.POLICY on the server, so both sides use the same rules.
  var pw = document.querySelector("[data-policy-input]");
  var rules = Array.prototype.slice.call(document.querySelectorAll(".rule[data-pattern]"));
  if (pw && rules.length) {
    var update = function () {
      rules.forEach(function (li) {
        var met = new RegExp(li.dataset.pattern).test(pw.value);
        li.classList.toggle("is-met", met);
      });
    };
    pw.addEventListener("input", update);
    update();
  }

  // 3. Confirm-password hint.
  var confirm = document.querySelector("[data-confirm-input]");
  var status = document.querySelector("[data-confirm-status]");
  if (pw && confirm && status) {
    var check = function () {
      if (!confirm.value) { status.textContent = ""; status.className = "field__hint field__hint--live"; return; }
      var same = confirm.value === pw.value;
      status.textContent = same ? "Passwords match." : "Passwords don't match yet.";
      status.className = "field__hint field__hint--live " + (same ? "is-ok" : "is-bad");
    };
    confirm.addEventListener("input", check);
    pw.addEventListener("input", check);
  }

  // 4. Show / hide password.
  document.querySelectorAll("[data-reveal]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.dataset.reveal);
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
      btn.setAttribute("aria-pressed", String(show));
    });
  });

  // 5. Copy buttons on the security lab page.
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = document.getElementById(btn.dataset.copy).textContent;
      var done = function () {
        btn.textContent = "Copied";
        btn.classList.add("is-done");
        setTimeout(function () { btn.textContent = "Copy"; btn.classList.remove("is-done"); }, 1600);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done);
      } else {
        // Plain-HTTP fallback (vulnerable build): select the text for manual copy.
        var range = document.createRange();
        range.selectNodeContents(document.getElementById(btn.dataset.copy));
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        btn.textContent = "Selected";
      }
    });
  });
})();
