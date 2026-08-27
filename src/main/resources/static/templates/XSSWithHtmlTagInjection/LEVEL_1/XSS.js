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
  parentContainer.textContent = data;
  if (parentContainer.childNodes.length > 0) {
    var firstChild = parentContainer.childNodes[0];
    // Only add class if the node is an element (textContent creates a text node)
    if (firstChild.nodeType === Node.ELEMENT_NODE) {
      firstChild.classList.add(document.getElementById("fonts").value);
    }
  }
}
