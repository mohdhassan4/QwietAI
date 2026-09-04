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
  // The response is an <img> tag built from the selected value. It is parsed
  // in an inert DOMParser document (no script runs, no resource is fetched)
  // and the image is re-created here from a validated relative src only, so
  // injected attributes such as onerror never become live DOM.
  var parsedImage = new DOMParser()
    .parseFromString(data, "text/html")
    .querySelector("img");
  var src = parsedImage ? parsedImage.getAttribute("src") || "" : "";
  if (!/^[\w./-]+$/.test(src)) {
    // Not a plain relative image path, so show the response as text instead.
    container.textContent = data;
    return;
  }
  var image = document.createElement("img");
  image.setAttribute("src", src);
  image.setAttribute("width", "400");
  image.setAttribute("height", "300");
  container.appendChild(image);
}
