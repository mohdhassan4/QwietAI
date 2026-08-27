function loadChallenge() {
  let url = getUrlForVulnerabilityLevel();
  doGetAjaxCall(displayChallenge, url, true);
}

function displayChallenge(data) {
  let challengeDiv = document.getElementById("challenge");
  challengeDiv.innerHTML = "";
  let strongEl = document.createElement("strong");
  strongEl.textContent = data.content;
  challengeDiv.appendChild(strongEl);
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
  resultDiv.innerHTML = "";
  let label = document.createElement("strong");
  label.textContent = "Result:";
  resultDiv.appendChild(label);
  resultDiv.appendChild(document.createTextNode(" " + data.content));
  if (data.isValid) {
    resultDiv.className = "result-success";
  } else {
    resultDiv.className = "result-failure";
  }
}

addingEventListenerToSubmitButton();
loadChallenge();
