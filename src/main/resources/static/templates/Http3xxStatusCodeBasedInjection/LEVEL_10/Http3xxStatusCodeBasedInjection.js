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

  var overlay = document.createElement("div");
  overlay.id = "redirect-overlay";
  Object.assign(overlay.style, {
    position: "fixed",
    top: "0",
    left: "0",
    width: "100%",
    height: "100%",
    background: "rgba(0, 0, 0, 0.75)",
    display: "none",
    alignItems: "center",
    justifyContent: "center",
    zIndex: "9999",
    boxSizing: "border-box",
  });

  var card = document.createElement("div");
  card.className = "redirect-modal-card";

  var iconWrap = document.createElement("div");
  iconWrap.className = "redirect-modal-icon-wrap";
  var icon = document.createElement("span");
  icon.className = "redirect-modal-icon";
  icon.textContent = "⚠";
  iconWrap.appendChild(icon);
  card.appendChild(iconWrap);

  var title = document.createElement("h2");
  title.className = "redirect-modal-title";
  title.textContent = "You are leaving VulnerableApp";
  card.appendChild(title);

  var subtitle = document.createElement("p");
  subtitle.className = "redirect-modal-subtitle";
  subtitle.textContent = "You are about to be redirected to an external site. Please review the destination before continuing.";
  card.appendChild(subtitle);

  var urlBox = document.createElement("div");
  urlBox.className = "redirect-url-box";
  var destSpan = document.createElement("span");
  destSpan.className = "redirect-dest-url";
  urlBox.appendChild(destSpan);
  card.appendChild(urlBox);

  var actions = document.createElement("div");
  actions.className = "redirect-modal-actions";
  var btnClose = document.createElement("button");
  btnClose.className = "btn-redirect-close";
  btnClose.textContent = "Close";
  var btnContinue = document.createElement("button");
  btnContinue.className = "btn-redirect-continue";
  btnContinue.textContent = "Continue";
  actions.appendChild(btnClose);
  actions.appendChild(btnContinue);
  card.appendChild(actions);

  overlay.appendChild(card);
  document.body.appendChild(overlay);

  anchor.addEventListener("click", function (event) {
    event.preventDefault();
    destSpan.textContent = "/VulnerableApp/phishing/fake-login.html";
    overlay.style.display = "flex";
  });

  btnContinue.addEventListener("click", function () {
    window.location.href = endpointUrl;
  });

  btnClose.addEventListener("click", function () {
    overlay.style.display = "none";
  });
}

updatePlaceholderDiv();
