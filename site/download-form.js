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

  var requestTimeoutMs = 5000;
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
      var controller = typeof window.AbortController === "function"
        ? new window.AbortController()
        : null;
      var requestOptions = {
        method: "POST",
        headers: { "Accept": "application/json" },
        body: new FormData(form)
      };
      if (controller) requestOptions.signal = controller.signal;

      var timeoutId;
      var timeout = new Promise(function (_resolve, reject) {
        timeoutId = window.setTimeout(function () {
          if (controller) controller.abort();
          reject(new Error("FormSubmit request timed out"));
        }, requestTimeoutMs);
      });
      var request = fetch(ajaxAction, requestOptions).then(function (response) {
        return response.json().then(function (payload) {
          return { response: response, payload: payload };
        });
      });
      var result = await Promise.race([request, timeout]);
      window.clearTimeout(timeoutId);
      var response = result.response;
      var payload = result.payload;

      if (!response.ok || (payload.success !== true && payload.success !== "true")) {
        throw new Error("FormSubmit did not confirm capture");
      }

      ready.hidden = false;
      status.textContent = "Request confirmed. Your download is ready.";
      form.reset();
      submit.disabled = false;
    } catch (error) {
      window.clearTimeout(timeoutId);
      ready.hidden = true;
      status.textContent = "Continuing with the standard request…";
      submit.disabled = false;
      form.submit();
    }
  });
}());
