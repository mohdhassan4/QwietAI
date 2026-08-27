function loadChallenge() {
  let url = getUrlForVulnerabilityLevel();
  doGetAjaxCall(displayChallenge, url, true);
}

function displayChallenge(data) {
  let challengeDiv = document.getElementById("challenge");
  challengeDiv.textContent = "";
  var strong = document.createElement("strong");
  strong.textContent = data.content;
  challengeDiv.appendChild(strong);
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
        resultDiv.textContent = "";
        var strongEl = document.createElement("strong");
        strongEl.textContent = "Please enter a password guess.";
        resultDiv.appendChild(strongEl);
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
  resultDiv.textContent = "";
  var strong = document.createElement("strong");
  strong.textContent = "Result:";
  resultDiv.appendChild(strong);
  resultDiv.appendChild(document.createTextNode(" " + data.content));
  if (data.isValid) {
    resultDiv.className = "result-success";
  } else {
    resultDiv.className = "result-failure";
  }
}

addingEventListenerToSubmitButton();
loadChallenge();
