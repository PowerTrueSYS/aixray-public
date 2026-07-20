(function () {
  "use strict";

  var form = document.getElementById("download-form");
  var ready = document.getElementById("download-ready");
  var status = document.getElementById("download-status");
  if (
    !form ||
    !ready ||
    !status ||
    typeof window.fetch !== "function" ||
    typeof window.FormData !== "function"
  ) {
    return;
  }

  var submit = form.querySelector('button[type="submit"]');
  if (!submit) return;

  ready.hidden = true;

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    ready.hidden = true;
    status.textContent = "Confirming your request…";
    submit.disabled = true;

    try {
      var ajaxAction = form.action.replace(
        "https://formsubmit.co/",
        "https://formsubmit.co/ajax/"
      );
      var response = await fetch(ajaxAction, {
        method: "POST",
        headers: { "Accept": "application/json" },
        body: new FormData(form)
      });
      var payload = await response.json();

      if (!response.ok || (payload.success !== true && payload.success !== "true")) {
        throw new Error("FormSubmit did not confirm capture");
      }

      ready.hidden = false;
      status.textContent = "Request confirmed. Your download is ready.";
      form.reset();
      submit.disabled = false;
    } catch (error) {
      ready.hidden = true;
      status.textContent = "Continuing with the standard request…";
      submit.disabled = false;
      form.submit();
    }
  });
}());
