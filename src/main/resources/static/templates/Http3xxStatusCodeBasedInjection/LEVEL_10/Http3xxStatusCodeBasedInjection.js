function createModalElement(tagName, className, text) {
  var element = document.createElement(tagName);
  element.className = className;
  if (text) {
    element.textContent = text;
  }
  return element;
}

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

  // The interstitial is built with DOM APIs rather than assigned as markup,
  // so no string ever reaches this element as HTML.
  var card = createModalElement("div", "redirect-modal-card");

  var iconWrap = createModalElement("div", "redirect-modal-icon-wrap");
  iconWrap.appendChild(createModalElement("span", "redirect-modal-icon", "⚠"));
  card.appendChild(iconWrap);

  var title = createModalElement("h2", "redirect-modal-title");
  title.textContent = "You are leaving VulnerableApp";
  card.appendChild(title);

  var subtitle = createModalElement("p", "redirect-modal-subtitle");
  subtitle.textContent =
    "You are about to be redirected to an external site. " +
    "Please review the destination before continuing.";
  card.appendChild(subtitle);

  var urlBox = createModalElement("div", "redirect-url-box");
  urlBox.appendChild(createModalElement("span", "redirect-dest-url"));
  card.appendChild(urlBox);

  var actions = createModalElement("div", "redirect-modal-actions");
  var closeButton = createModalElement("button", "btn-redirect-close");
  closeButton.textContent = "Close";
  var continueButton = createModalElement("button", "btn-redirect-continue");
  continueButton.textContent = "Continue";
  actions.appendChild(closeButton);
  actions.appendChild(continueButton);
  card.appendChild(actions);

  overlay.appendChild(card);

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
