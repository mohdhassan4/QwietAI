function loadChallenge() {
  let url = getUrlForVulnerabilityLevel();
  doGetAjaxCall(displayChallenge, url, true);
}

// Renders "<strong>label</strong> value" style output with the server
// provided value added as text, so it can never introduce markup.
function renderAsBoldText(target, content) {
  target.textContent = "";
  let boldText = document.createElement("strong");
  boldText.textContent = content;
  target.appendChild(boldText);
}

function renderLabelledResult(target, label, content) {
  target.textContent = "";
  let labelElement = document.createElement("strong");
  labelElement.textContent = label;
  target.appendChild(labelElement);
  target.appendChild(document.createTextNode(" " + content));
}

function displayChallenge(data) {
  let challengeDiv = document.getElementById("challenge");
  renderAsBoldText(challengeDiv, data.content);
  if (data.isValid) {
    challengeDiv.className = "challenge-secure";
  } else {
    challengeDiv.className = "challenge-vulnerable";
  }
}

function addingEventListenerToSubmitButton() {
  document
    .getElementById("submitButton")
    .addEventListener("click", function () {
      let url = getUrlForVulnerabilityLevel();
      let password = document.getElementById("password").value;

      if (!password) {
        let resultDiv = document.getElementById("result");
        resultDiv.innerHTML = "<strong>Please enter a password guess.</strong>";
        resultDiv.style.color = "red";
        return;
      }

      let params = new URLSearchParams();
      params.append("password", password);

      doGetAjaxCall(
        appendResponseCallback,
        url + "?" + params.toString(),
        true
      );
    });
}

function appendResponseCallback(data) {
  let resultDiv = document.getElementById("result");
  if (data.isValid) {
    renderLabelledResult(resultDiv, "Result:", data.content);
    resultDiv.className = "result-success";
  } else {
    renderLabelledResult(resultDiv, "Result:", data.content);
    resultDiv.className = "result-failure";
  }
}

addingEventListenerToSubmitButton();
loadChallenge();
