function addingEventListenerToLoadImageButton() {
  document.getElementById("loadImage").addEventListener("click", function () {
    let url = getUrlForVulnerabilityLevel();
    doGetAjaxCall(
      appendResponseCallback,
      url +
        "?src=/VulnerableApp/images/" +
        document.getElementById("images").value,
      false
    );
  });
}
addingEventListenerToLoadImageButton();

function appendResponseCallback(data) {
  var container = document.getElementById("image");
  container.textContent = "";
  var doc = new DOMParser().parseFromString(data, "text/html");
  Array.from(doc.body.childNodes).forEach(function (node) {
    container.appendChild(document.adoptNode(node));
  });
}
