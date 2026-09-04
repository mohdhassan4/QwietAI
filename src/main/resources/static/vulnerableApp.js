const detail = document.querySelector(".detail");
const detailTitle = document.querySelector(".detail-title");
const master = document.querySelector(".master");
const innerMaster = document.querySelector(".inner-master");

const variantTooltip = {
  secure: "Secure implementation",
  unsecure: "Unsecure implementation",
};

let vulnerabilitySelected = "";
let vulnerabilityLevelSelected = "";

const MODE_SCANNER = "SCANNER";
const MODE_CHALLENGE = "CHALLENGE";
let appMode = MODE_SCANNER;

let currentId;
let currentKey;
// Incrementing token identifying the most recent navigation/request.
// currentId/currentKey alone can't distinguish A -> B -> A (same id/key
// selected twice), so every async callback validates against this token
// instead, and only acts if it's still the most recent request.
let requestToken = 0;

// Elements/attributes that may survive when rendering markup which is not a
// constant (vulnerability descriptions and level responses built by the
// server) but still has to look like formatted content. Anything else -
// script/img/svg/object tags, inline event handlers, unsafe URL schemes - is
// dropped instead of becoming live DOM in this page.
const SAFE_HTML_ELEMENTS = {
  A: ["href", "target", "rel", "class"],
  B: ["class"],
  BR: [],
  CODE: ["class"],
  DIV: ["class"],
  EM: ["class"],
  H3: ["class"],
  H4: ["class"],
  HR: [],
  I: ["class"],
  IFRAME: ["src", "class"],
  LI: ["class"],
  OL: ["class"],
  P: ["class"],
  PRE: ["class"],
  SECTION: ["class"],
  SPAN: ["class"],
  STRONG: ["class"],
  U: ["class"],
  UL: ["class"],
};

// http(s), mailto, fragment and relative URLs only, so href/src can never
// carry a javascript:/data: payload.
const SAFE_URL_PATTERN = /^(?:https?:\/\/|mailto:|[\w.,~%+-]*(?:[/?#]|$))/i;

function _isSafeUrlValue(value) {
  return SAFE_URL_PATTERN.test(String(value).trim());
}

/**
 * Convert a node parsed out of non-constant markup into a node that is safe
 * to attach to this document. Elements that are not allowlisted are replaced
 * by their text, so their content is still visible but inert.
 */
function _toSafeHtmlNode(node) {
  if (node.nodeType === Node.TEXT_NODE) {
    return document.createTextNode(node.nodeValue);
  }
  if (node.nodeType !== Node.ELEMENT_NODE) {
    return null;
  }
  let allowedAttributes = SAFE_HTML_ELEMENTS[node.tagName];
  if (!allowedAttributes) {
    return document.createTextNode(node.textContent);
  }
  let safeElement = document.createElement(node.tagName.toLowerCase());
  for (let attribute of allowedAttributes) {
    let value = node.getAttribute(attribute);
    if (value === null) {
      continue;
    }
    if (
      (attribute === "href" || attribute === "src") &&
      !_isSafeUrlValue(value)
    ) {
      continue;
    }
    safeElement.setAttribute(attribute, value);
  }
  if (safeElement.tagName === "A" && safeElement.target === "_blank") {
    safeElement.setAttribute("rel", "noopener noreferrer");
  }
  for (let child of node.childNodes) {
    let safeChild = _toSafeHtmlNode(child);
    if (safeChild) {
      safeElement.appendChild(safeChild);
    }
  }
  return safeElement;
}

/**
 * Render formatted markup that is not a constant into `target` without ever
 * assigning it as HTML: it is parsed into an inert DOMParser document (no
 * script runs and no resource is fetched there) and only the allowlisted
 * elements/attributes are re-created inside this document.
 * @param {Element} target - element whose content is replaced
 * @param {string} markup - markup coming from the server
 */
function renderSafeHtml(target, markup) {
  target.textContent = "";
  let parsedBody = new DOMParser().parseFromString(
    markup == null ? "" : String(markup),
    "text/html"
  ).body;
  for (let child of parsedBody.childNodes) {
    let safeChild = _toSafeHtmlNode(child);
    if (safeChild) {
      target.appendChild(safeChild);
    }
  }
}

/**
 * Append a "<b>label</b> value" pair to `parent`, with `value` added as text
 * so it can never introduce markup.
 * @param {Element} parent - element the pair is appended to
 * @param {string} label - constant label
 * @param {string} value - dynamic value, rendered as text
 */
function _appendLabelledText(parent, label, value) {
  let labelElement = document.createElement("b");
  labelElement.textContent = label;
  parent.appendChild(labelElement);
  let text = value == null ? "" : String(value);
  parent.appendChild(document.createTextNode(" " + text));
}

function _loadDynamicJSAndCSS(urlToFetchHtmlTemplate, onReady) {
  let dynamicScriptsElement = document.getElementById("dynamicScripts");
  let cssElement = document.createElement("link");
  cssElement.href = urlToFetchHtmlTemplate + ".css";
  cssElement.type = "text/css";
  cssElement.rel = "stylesheet";

  let reveal = function () {
    if (typeof onReady === "function") {
      onReady();
    }
  };

  if (urlToFetchHtmlTemplate === "error") {
    document.getElementById("hideHelp").style.display = "none";
    document.getElementById("showHelp").style.display = "none";
    // Only one asset (CSS) to wait for in the error case.
    cssElement.addEventListener("load", reveal);
    cssElement.addEventListener("error", reveal);
    dynamicScriptsElement.appendChild(cssElement);
  } else {
    document.getElementById("hideHelp").style.display = "inline-block";
    document.getElementById("showHelp").style.display = "inline-block";
    let jsElement = document.createElement("script");
    jsElement.type = "module";
    jsElement.src = urlToFetchHtmlTemplate + ".js?p=" + new Date().getTime();

    let cssLoaded = false;
    let jsLoaded = false;
    let maybeReveal = function () {
      if (cssLoaded && jsLoaded) {
        reveal();
      }
    };
    // Fall back to revealing even if an asset 404s/errors, so navigation
    // never gets stuck hidden.
    let onCssSettled = function () {
      cssLoaded = true;
      maybeReveal();
    };
    let onJsSettled = function () {
      jsLoaded = true;
      maybeReveal();
    };
    cssElement.addEventListener("load", onCssSettled);
    cssElement.addEventListener("error", onCssSettled);
    jsElement.addEventListener("load", onJsSettled);
    jsElement.addEventListener("error", onJsSettled);

    dynamicScriptsElement.appendChild(cssElement);
    dynamicScriptsElement.appendChild(jsElement);
  }
}

function _callbackForInnerMasterOnClickEvent(
  vulnerableAppEndPointData,
  id,
  key,
  vulnerabilitySelected
) {
  return function () {
    if (currentId == id && currentKey == key) {
      return;
    }
    currentId = id;
    currentKey = key;
    // Mint a token for this navigation. Every async callback below
    // captures it and re-checks it before touching shared state, so a
    // stale in-flight request (even a repeat of the same id/key from an
    // A -> B -> A sequence) can never win against a newer one.
    requestToken += 1;
    const thisRequestToken = requestToken;
    clearSelectedInnerMaster();
    vulnerabilityLevelSelected =
      vulnerableAppEndPointData[id]["Detailed Information"][key]["Level"];
    this.classList.add("active-item");
    let levelChallengeCards = _getChallengeCardsForLevel(
      vulnerableAppEndPointData,
      id,
      key
    );
    _updateChallengeToggleAvailability(levelChallengeCards);
    _renderDetailMode(vulnerableAppEndPointData);
    let htmlTemplate =
      vulnerableAppEndPointData[id]["Detailed Information"][key][
        "HtmlTemplate"
      ];
    renderSafeHtml(
      document.getElementById("vulnerabilityDescription"),
      vulnerableAppEndPointData[id]["Description"]
    );
    let urlToFetchHtmlTemplate = htmlTemplate
      ? "/VulnerableApp/templates/" + vulnerabilitySelected + "/" + htmlTemplate
      : "error";
    let parentNodeWithAllDynamicScripts =
      document.getElementById("dynamicScripts");
    let dynamicScriptNode = parentNodeWithAllDynamicScripts.lastElementChild;
    //Might not require to iterate but iterating for safe side. can be removed after proper testing.
    while (dynamicScriptNode) {
      dynamicScriptNode.remove();
      dynamicScriptNode = parentNodeWithAllDynamicScripts.lastElementChild;
    }
    // Hide the detail title area until the new template's CSS/JS have
    // actually loaded, so the browser never paints unstyled content.
    detailTitle.classList.add("content-loading");
    doGetAjaxCall(
      (responseText) => {
        // Discard stale responses: if the user has navigated again while
        // this request was in flight, requestToken will have moved on.
        if (requestToken !== thisRequestToken) {
          return;
        }
        detailTitle.innerHTML = responseText;
        _loadDynamicJSAndCSS(urlToFetchHtmlTemplate, () => {
          // Re-check: the asset load itself is async, so navigation could
          // have moved on again between the AJAX response and now.
          if (requestToken !== thisRequestToken) {
            return;
          }
          detailTitle.classList.remove("content-loading");
        });
      },
      urlToFetchHtmlTemplate + ".html",
      false,
      {},
      () => {
        // Covers both network-level failures and terminal HTTP errors
        // (4xx/5xx) — don't leave the pane hidden forever.
        if (requestToken === thisRequestToken) {
          detailTitle.classList.remove("content-loading");
        }
      }
    );
  };
}

function _isSecureVariant(detailedInformation) {
  return detailedInformation["Variant"] === "SECURE";
}

function _getSvgElementForVariant(isSecure) {
  let svg = document.createElement("img");
  svg.classList.add("vector");
  svg.classList.add("tooltip");
  const svgVariantName = isSecure ? "secure" : "unsecure";

  svg.setAttribute("src", "vectors/" + svgVariantName + ".svg");

  return svg;
}

function createColumn(detailedInformationArray, key) {
  let detailedInformation = detailedInformationArray[key];
  let isSecure = _isSecureVariant(detailedInformation);

  let column = document.createElement("div");
  column.id = "0." + key;

  let svgWithTooltip = document.createElement("div");
  svgWithTooltip.classList.add("tooltip");

  let span = document.createElement("span");
  span.classList.add("tooltip-text");
  span.classList.add(
    isSecure ? "secure-variant-tooltip-text" : "unsecure-variant-tooltip-text"
  );
  span.textContent = isSecure ? variantTooltip.secure : variantTooltip.unsecure;
  svgWithTooltip.appendChild(span);
  svgWithTooltip.appendChild(_getSvgElementForVariant(isSecure));
  column.appendChild(svgWithTooltip);

  column.appendChild(document.createTextNode(detailedInformation["Level"]));
  column.classList.add("inner-master-item");

  if (isSecure) {
    column.classList.add("secure-vulnerability");
  }

  return column;
}

function appendNewColumn(vulnerableAppEndPointData, id) {
  let detailedInformationArray =
    vulnerableAppEndPointData[id]["Detailed Information"];
  let isFirst = true;

  for (let key in detailedInformationArray) {
    if (!detailedInformationArray.hasOwnProperty(key)) {
      continue;
    }
    let column = createColumn(detailedInformationArray, key);
    column.addEventListener(
      "click",
      _callbackForInnerMasterOnClickEvent(
        vulnerableAppEndPointData,
        id,
        key,
        vulnerabilitySelected
      )
    );
    if (isFirst) {
      column.click();
      isFirst = false;
    }
    innerMaster.appendChild(column);
  }
}

/**
 * Replace vulnerability description and append a column with all of the vulnerability levels.
 * Each level is assigned with an event listener that aims to handle specific level selection.
 * @param {Object} vulnerableAppEndPointData - data from the API describing the vulnerability
 * @param {number} id - master-item identifier
 */
function handleElementAutoSelection(vulnerableAppEndPointData, id = 0) {
  if (!vulnerableAppEndPointData.length) {
    return;
  }

  if (id === 0) {
    renderSafeHtml(detailTitle, vulnerableAppEndPointData[id]["Description"]);
  } else {
    innerMaster.innerHTML = "";
  }

  vulnerabilitySelected = vulnerableAppEndPointData[id]["Name"];
  renderSafeHtml(detailTitle, vulnerableAppEndPointData[id]["Description"]);
  appendNewColumn(vulnerableAppEndPointData, id);
}

function update(vulnerableAppEndPointData) {
  const masterItems = document.querySelectorAll(".master-item");
  handleElementAutoSelection(vulnerableAppEndPointData, 0);
  masterItems.forEach((item) => {
    item.addEventListener("click", function () {
      clearSelectedMaster();
      this.classList.add("active-item");
      detail.classList.remove("hidden-md-down");
      handleElementAutoSelection(vulnerableAppEndPointData, this.id);
    });
  });
  _addingEventListenerToShowHideHelpButton(vulnerableAppEndPointData);
  _addingEventListenerToModeToggle(vulnerableAppEndPointData);
}

function _clearActiveItemClass(items) {
  for (let item of items) {
    //to clear out the already active item
    item.classList.remove("active-item");
  }
}

function clearSelectedMaster() {
  //console.log('Clicked item');
  const masterItems = document.querySelectorAll(".master-item");
  //Making back to learning vulnerability
  document.getElementById("vulnLearnBtn").click();
  _clearActiveItemClass(masterItems);
  _clearHelp();
}

function clearSelectedInnerMaster() {
  //console.log('Clicked item');
  const innerMasterItems = document.querySelectorAll(".inner-master-item");
  _clearActiveItemClass(innerMasterItems);
  _clearHelp();
}

function back() {
  detail.classList.add("hidden-md-down");
  clearSelected();
}

function getUrlForVulnerability() {
  return "/VulnerableApp/" + vulnerabilitySelected;
}

function getUrlForVulnerabilityLevel() {
  return (
    "/VulnerableApp/" + vulnerabilitySelected + "/" + vulnerabilityLevelSelected
  );
}

function getCurrentVulnerabilityLevel() {
  return vulnerabilityLevelSelected;
}

function genericResponseHandler(xmlHttpRequest, callBack, isJson, onError) {
  if (xmlHttpRequest.readyState == XMLHttpRequest.DONE) {
    // XMLHttpRequest.DONE == 4
    if (
      xmlHttpRequest.status == 200 ||
      xmlHttpRequest.status == 401 ||
      xmlHttpRequest.status == 403
    ) {
      if (isJson) {
        callBack(JSON.parse(xmlHttpRequest.responseText), xmlHttpRequest);
      } else {
        callBack(xmlHttpRequest.responseText, xmlHttpRequest);
      }
    } else if (xmlHttpRequest.status == 400) {
      alert("There was an error 400");
      if (typeof onError === "function") {
        onError(xmlHttpRequest);
      }
    } else {
      alert("something else other than 200/401/403/404 was returned");
      if (typeof onError === "function") {
        onError(xmlHttpRequest);
      }
    }
  }
}

function doGetAjaxCall(callBack, url, isJson, headers = {}, onError) {
  let xmlHttpRequest = new XMLHttpRequest();
  // Guard against onError firing twice: a network failure can cause
  // readystatechange to reach DONE with status 0 (routed through
  // genericResponseHandler's error branch) *and* trigger onerror below.
  let errorReported = false;
  let reportError = function () {
    if (errorReported) {
      return;
    }
    errorReported = true;
    if (typeof onError === "function") {
      onError(xmlHttpRequest);
    }
  };
  xmlHttpRequest.onreadystatechange = function () {
    genericResponseHandler(xmlHttpRequest, callBack, isJson, reportError);
  };
  xmlHttpRequest.onerror = function () {
    // Network-level failure (e.g. offline, DNS, CORS) — readystatechange
    // may or may not reach DONE in this case, so reportError() is the
    // single-shot funnel for both paths.
    reportError();
  };
  xmlHttpRequest.open("GET", url, true);
  xmlHttpRequest.setRequestHeader(
    "Content-Type",
    isJson ? "application/json" : "text/html"
  );

  for (const header in headers) {
    xmlHttpRequest.setRequestHeader(header, headers[header]);
  }

  xmlHttpRequest.send();
}

function doPostAjaxCall(callBack, url, isJson, data, headers = {}) {
  let xmlHttpRequest = new XMLHttpRequest();
  xmlHttpRequest.onreadystatechange = function () {
    return genericResponseHandler(xmlHttpRequest, callBack, isJson);
  };
  xmlHttpRequest.open("POST", url, true);
  for (const header in headers) {
    xmlHttpRequest.setRequestHeader(header, headers[header]);
  }
  xmlHttpRequest.send(data);
}

function generateMasterDetail(vulnerableAppEndPointData) {
  let isFirst = true;
  for (let index in vulnerableAppEndPointData) {
    let column = document.createElement("div");
    if (isFirst) {
      column.className = "master-item  active-item";
      isFirst = false;
    } else {
      column.className = "master-item";
    }
    column.id = index;
    let textNode = document.createTextNode(
      vulnerableAppEndPointData[index]["Name"]
    );
    column.appendChild(textNode);
    master.appendChild(column);
  }
  update(vulnerableAppEndPointData);
}

function _clearHelp() {
  document.getElementById("showHelp").disabled = false;
  document.getElementById("helpText").innerHTML = "";
  document.getElementById("hideHelp").disabled = true;
}

function _addingEventListenerToShowHideHelpButton(vulnerableAppEndPointData) {
  document.getElementById("showHelp").addEventListener("click", function () {
    document.getElementById("showHelp").disabled = true;
    // Attack vector descriptions and payloads are built as DOM nodes with the
    // dynamic parts added as text: payloads legitimately contain markup like
    // <script>alert(1)</script> and must be shown, never executed here.
    let helpList = document.createElement("ol");
    for (let index in vulnerableAppEndPointData[currentId][
      "Detailed Information"
    ][currentKey]["AttackVectors"]) {
      let attackVector =
        vulnerableAppEndPointData[currentId]["Detailed Information"][
          currentKey
        ]["AttackVectors"][index];
      let curlPayload = attackVector["CurlPayload"];
      let description = attackVector["Description"];
      let helpItem = document.createElement("li");
      _appendLabelledText(
        helpItem,
        "Description about the attack:",
        description
      );
      helpItem.appendChild(document.createElement("br"));
      _appendLabelledText(helpItem, "Payload:", curlPayload);
      helpList.appendChild(helpItem);
    }
    let helpTextElement = document.getElementById("helpText");
    helpTextElement.textContent = "";
    helpTextElement.appendChild(helpList);
    document.getElementById("hideHelp").disabled = false;
  });

  document.getElementById("hideHelp").addEventListener("click", function () {
    _clearHelp();
  });
}

function _isChallengeAvailable(challengeCards) {
  return Array.isArray(challengeCards) && challengeCards.length > 0;
}

function _buildSingleChallengeCard(card, index) {
  let cardEl = document.createElement("div");
  cardEl.classList.add("challenge-card");

  let header = document.createElement("div");
  header.classList.add("challenge-card-header");
  let title = document.createElement("span");
  title.classList.add("challenge-card-title");
  title.textContent = "Challenge " + (index + 1);
  header.appendChild(title);

  let body = document.createElement("div");
  body.classList.add("challenge-card-body");

  let objective = document.createElement("p");
  objective.classList.add("challenge-card-objective");
  objective.textContent = card["ChallengeText"] || "";
  body.appendChild(objective);

  let hints = (card["hints"] || []).slice().sort(function (a, b) {
    return (a["order"] || 0) - (b["order"] || 0);
  });
  let hintList = document.createElement("ol");
  hintList.classList.add("challenge-card-hints");
  body.appendChild(hintList);

  let payload = card["payload"];

  let revealHintBtn = document.createElement("button");
  revealHintBtn.type = "button";
  revealHintBtn.classList.add("challenge-card-reveal-hint");
  revealHintBtn.textContent = "Reveal hint";

  // Payload controls only exist when the card has a payload.
  let showPayloadBtn = null;
  let payloadEl = null;
  if (payload) {
    showPayloadBtn = document.createElement("button");
    showPayloadBtn.type = "button";
    showPayloadBtn.classList.add("challenge-card-show-payload");
    showPayloadBtn.textContent = "Show Payload";
    showPayloadBtn.disabled = true;

    payloadEl = document.createElement("div");
    payloadEl.classList.add("challenge-card-payload", "hide-component");

    showPayloadBtn.addEventListener("click", function () {
      payloadEl.innerHTML = "";
      let desc = document.createElement("p");
      desc.classList.add("challenge-card-payload-description");
      desc.textContent = payload["description"] || "";
      let value = document.createElement("code");
      value.classList.add("challenge-card-payload-value");
      value.textContent = payload["value"] || "";
      payloadEl.appendChild(desc);
      payloadEl.appendChild(value);
      payloadEl.classList.remove("hide-component");
    });
  }

  let revealedHints = 0;
  function _updateControlsAfterHint() {
    if (revealedHints >= hints.length) {
      revealHintBtn.classList.add("hide-component");
      if (payload) {
        showPayloadBtn.disabled = false;
      }
    }
  }

  revealHintBtn.addEventListener("click", function () {
    if (revealedHints < hints.length) {
      let li = document.createElement("li");
      li.textContent = hints[revealedHints]["text"] || "";
      hintList.appendChild(li);
      revealedHints += 1;
      _updateControlsAfterHint();
    }
  });

  if (hints.length === 0) {
    revealHintBtn.classList.add("hide-component");
    if (payload) {
      showPayloadBtn.disabled = false;
    }
  }

  body.appendChild(revealHintBtn);
  if (payload) {
    body.appendChild(showPayloadBtn);
    body.appendChild(payloadEl);
  }

  cardEl.appendChild(header);
  cardEl.appendChild(body);
  return cardEl;
}

function buildChallengeCards(challengeCardArray) {
  let container = document.createElement("div");
  container.classList.add("challenge-cards-grid");
  if (!Array.isArray(challengeCardArray) || challengeCardArray.length === 0) {
    return container;
  }
  challengeCardArray.forEach(function (card, index) {
    container.appendChild(_buildSingleChallengeCard(card, index));
  });
  return container;
}

function _setAppMode(mode) {
  appMode = mode;
  document
    .getElementById("scannerModeBtn")
    .classList.toggle("active-mode", mode === MODE_SCANNER);
  document
    .getElementById("challengeModeBtn")
    .classList.toggle("active-mode", mode === MODE_CHALLENGE);
}

function _updateChallengeToggleAvailability(challengeCards) {
  let available = _isChallengeAvailable(challengeCards);
  document.getElementById("challengeModeBtn").disabled = !available;
  if (!available && appMode === MODE_CHALLENGE) {
    _setAppMode(MODE_SCANNER);
  }
}

function _getChallengeCardsForLevel(vulnerableAppEndPointData, id, key) {
  let level =
    vulnerableAppEndPointData[id] &&
    vulnerableAppEndPointData[id]["Detailed Information"][key];
  return (level && level["ChallengeCard"]) || [];
}

function _renderDetailMode(vulnerableAppEndPointData) {
  let challengeCardsContainer = document.getElementById("challengeCards");
  let scannerHelp = document.getElementById("scannerHelp");
  let challengeCards = _getChallengeCardsForLevel(
    vulnerableAppEndPointData,
    currentId,
    currentKey
  );

  challengeCardsContainer.innerHTML = "";
  if (appMode === MODE_CHALLENGE) {
    if (_isChallengeAvailable(challengeCards)) {
      challengeCardsContainer.appendChild(buildChallengeCards(challengeCards));
    } else {
      let placeholder = document.createElement("p");
      placeholder.classList.add("challenge-cards-empty");
      placeholder.textContent = "No challenges available for this level yet.";
      challengeCardsContainer.appendChild(placeholder);
    }
    challengeCardsContainer.classList.remove("hide-component");
    scannerHelp.classList.add("hide-component");
  } else {
    challengeCardsContainer.classList.add("hide-component");
    scannerHelp.classList.remove("hide-component");
  }
}

function _addingEventListenerToModeToggle(vulnerableAppEndPointData) {
  // Each segment selects its own mode
  function _selectMode(targetMode) {
    if (targetMode === appMode) {
      return;
    }
    // Challenge can be disabled for the current level (no challenge cards)
    // never switch into a disabled mode.
    if (
      targetMode === MODE_CHALLENGE &&
      document.getElementById("challengeModeBtn").disabled
    ) {
      return;
    }
    _setAppMode(targetMode);
    _renderDetailMode(vulnerableAppEndPointData);
  }

  document
    .getElementById("scannerModeBtn")
    .addEventListener("click", function () {
      _selectMode(MODE_SCANNER);
    });
  document
    .getElementById("challengeModeBtn")
    .addEventListener("click", function () {
      _selectMode(MODE_CHALLENGE);
    });
}

/**
 * Autoregistered Event listeners
 */
(function _autoRegister() {
  document
    .getElementById("learnAndPracticeBtn")
    .addEventListener("click", () => {
      document.getElementById("testScanner").classList.add("hide-component");
      document
        .getElementById("learnAndPractice")
        .classList.remove("hide-component");
      document.getElementById("chooseMode").classList.add("hide-component");
    });

  document.getElementById("testScannerBtn").addEventListener("click", () => {
    document.getElementById("testScanner").classList.remove("hide-component");
    document.getElementById("learnAndPractice").classList.add("hide-component");
    document.getElementById("chooseMode").classList.add("hide-component");
  });

  document.getElementById("vulnPracticeBtn").addEventListener("click", () => {
    document.getElementById("vulnPractice").classList.remove("hide-component");
    document
      .getElementById("vulnerabilityDescription")
      .classList.add("hide-component");
    document.getElementById("vulnLearnBtn").classList.remove("hide-component");
    document.getElementById("vulnPracticeBtn").classList.add("hide-component");
  });

  document.getElementById("vulnLearnBtn").addEventListener("click", () => {
    document.getElementById("vulnPractice").classList.add("hide-component");
    document
      .getElementById("vulnerabilityDescription")
      .classList.remove("hide-component");
    document
      .getElementById("vulnPracticeBtn")
      .classList.remove("hide-component");
    document.getElementById("vulnLearnBtn").classList.add("hide-component");
  });

  //  document.getElementById("about").addEventListener("click", () => {
  //    document.getElementById("aboutContainer").scrollIntoView(true);
  //  });
})();
