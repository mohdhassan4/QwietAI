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
  var img = doc.querySelector("img");
  if (img) {
    var safeImg = document.createElement("img");
    safeImg.src = img.getAttribute("src") || "";
    safeImg.alt = img.getAttribute("alt") || "";
    container.appendChild(safeImg);
  } else {
    container.textContent = data;
  }
}
