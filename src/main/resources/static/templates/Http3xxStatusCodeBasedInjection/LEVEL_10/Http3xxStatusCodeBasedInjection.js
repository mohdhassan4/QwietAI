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

  var modalCard = document.createElement("div");
  modalCard.className = "redirect-modal-card";

  var iconWrap = document.createElement("div");
  iconWrap.className = "redirect-modal-icon-wrap";
  var icon = document.createElement("span");
  icon.className = "redirect-modal-icon";
  icon.textContent = "⚠";
  iconWrap.appendChild(icon);
  modalCard.appendChild(iconWrap);

  var title = document.createElement("h2");
  title.className = "redirect-modal-title";
  title.textContent = "You are leaving VulnerableApp";
  modalCard.appendChild(title);

  var subtitle = document.createElement("p");
  subtitle.className = "redirect-modal-subtitle";
  subtitle.textContent = "You are about to be redirected to an external site. Please review the destination before continuing.";
  modalCard.appendChild(subtitle);

  var urlBox = document.createElement("div");
  urlBox.className = "redirect-url-box";
  var destUrl = document.createElement("span");
  destUrl.className = "redirect-dest-url";
  urlBox.appendChild(destUrl);
  modalCard.appendChild(urlBox);

  var actions = document.createElement("div");
  actions.className = "redirect-modal-actions";
  var closeBtn = document.createElement("button");
  closeBtn.className = "btn-redirect-close";
  closeBtn.textContent = "Close";
  var continueBtn = document.createElement("button");
  continueBtn.className = "btn-redirect-continue";
  continueBtn.textContent = "Continue";
  actions.appendChild(closeBtn);
  actions.appendChild(continueBtn);
  modalCard.appendChild(actions);

  overlay.appendChild(modalCard);

  document.body.appendChild(overlay);

  var destSpan = overlay.querySelector(".redirect-dest-url");
  var btnContinue = overlay.querySelector(".btn-redirect-continue");
  var btnClose = overlay.querySelector(".btn-redirect-close");

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
