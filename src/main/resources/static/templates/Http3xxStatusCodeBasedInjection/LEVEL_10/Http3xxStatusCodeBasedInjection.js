function updatePlaceholderDiv() {
  var endpointUrl =
    getUrlForVulnerabilityLevel() +
    "?returnTo=/VulnerableApp/phishing/fake-login.html";

  var anchor = document.getElementById("placeholder");
  anchor.href = endpointUrl;
  anchor.innerText = "Click here";

  // Remove any overlay left over from a previous level load
  var existing = document.getElementById("redirect-overlay");
  if (existing) {
    existing.remove();
  }

  // Build the overlay and append directly to <body>.
  // Critical layout styles are set inline so they apply immediately,
  // independent of when the external CSS file finishes loading.
  var overlay = document.createElement("div");
  overlay.id = "redirect-overlay";
  Object.assign(overlay.style, {
    position: "fixed",
    top: "0",
    left: "0",
    width: "100%",
    height: "100%",
    background: "rgba(0, 0, 0, 0.75)",
    display: "none", // hidden until the link is clicked
    alignItems: "center",
    justifyContent: "center",
    zIndex: "9999",
    boxSizing: "border-box",
  });

  overlay.innerHTML = sanitizeHTML(
    '<div class="redirect-modal-card">' +
    '<div class="redirect-modal-icon-wrap">' +
    '<span class="redirect-modal-icon">&#9888;</span>' +
    "</div>" +
    '<h2 class="redirect-modal-title">You are leaving VulnerableApp</h2>' +
    '<p class="redirect-modal-subtitle">You are about to be redirected to an external site. Please review the destination before continuing.</p>' +
    '<div class="redirect-url-box"><span class="redirect-dest-url"></span></div>' +
    '<div class="redirect-modal-actions">' +
    "</div>" +
    "</div>"
  );
  // Buttons are removed by sanitizer (not in allowlist); create them via DOM API
  var actionsDiv = overlay.querySelector(".redirect-modal-actions");
  var btnClose = document.createElement("button");
  btnClose.className = "btn-redirect-close";
  btnClose.textContent = "Close";
  actionsDiv.appendChild(btnClose);
  var btnContinue = document.createElement("button");
  btnContinue.className = "btn-redirect-continue";
  btnContinue.textContent = "Continue";
  actionsDiv.appendChild(btnContinue);

  document.body.appendChild(overlay);

  var destSpan = overlay.querySelector(".redirect-dest-url");

  // Intercept the link click — show the interstitial popup instead of navigating
  anchor.addEventListener("click", function (event) {
    event.preventDefault();
    destSpan.textContent = "/VulnerableApp/phishing/fake-login.html";
    overlay.style.display = "flex"; // reveal the overlay
  });

  // Continue: navigate to the endpoint; server returns 302 → browser follows to fake-login
  btnContinue.addEventListener("click", function () {
    window.location.href = endpointUrl;
  });

  // Close: dismiss the popup without navigating
  btnClose.addEventListener("click", function () {
    overlay.style.display = "none"; // hide the overlay
  });
}

updatePlaceholderDiv();
