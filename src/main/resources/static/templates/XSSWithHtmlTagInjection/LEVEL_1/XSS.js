function addingEventListenerToLoadImageButton() {
  document.getElementById("submit").addEventListener("click", function () {
    let url = getUrlForVulnerabilityLevel();
    doGetAjaxCall(
      appendResponseCallback,
      url + "?value=" + document.getElementById("textInput").value,
      false
    );
  });
}
addingEventListenerToLoadImageButton();

function appendResponseCallback(data) {
  var parentContainer = document.getElementById("parentContainer");
  // The response wraps the reflected value in a div. It is parsed in an inert
  // DOMParser document (no script runs, no resource is fetched) and only its
  // text is rendered, inside a div this page creates itself, so the reflected
  // value can never become live DOM here.
  var responseText = new DOMParser().parseFromString(data, "text/html").body
    .textContent;
  var responseElement = document.createElement("div");
  responseElement.textContent = responseText;
  responseElement.classList.add(document.getElementById("fonts").value);
  parentContainer.textContent = "";
  parentContainer.appendChild(responseElement);
}
