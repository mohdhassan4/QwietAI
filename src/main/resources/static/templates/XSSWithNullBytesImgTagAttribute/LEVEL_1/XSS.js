function addingEventListenerToLoadImageButton() {
  document.getElementById("loadImage").addEventListener("click", function () {
    let url = getUrlForVulnerabilityLevel();
    doGetAjaxCall(
      appendResponseCallback,
      url + "?value=images/" + document.getElementById("images").value,
      false
    );
  });
}
addingEventListenerToLoadImageButton();

function appendResponseCallback(data) {
  var container = document.getElementById("image");
  container.textContent = "";
  var parser = new DOMParser();
  var doc = parser.parseFromString(data, "text/html");
  var img = doc.querySelector("img");
  if (img) {
    var safeImg = document.createElement("img");
    var src = img.getAttribute("src") || "";
    if (src && !/^\s*javascript:/i.test(src)) {
      safeImg.setAttribute("src", src);
    }
    var width = img.getAttribute("width");
    if (width) {
      safeImg.setAttribute("width", width);
    }
    var alt = img.getAttribute("alt");
    if (alt) {
      safeImg.setAttribute("alt", alt);
    }
    container.appendChild(safeImg);
  } else {
    container.textContent = data;
  }
}
