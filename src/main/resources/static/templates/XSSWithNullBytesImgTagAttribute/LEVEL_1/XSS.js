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
  let container = document.getElementById("image");
  container.textContent = "";
  let parser = new DOMParser();
  let doc = parser.parseFromString(data, "text/html");
  let img = doc.querySelector("img");
  if (img) {
    let safeImg = document.createElement("img");
    safeImg.src = img.getAttribute("src") || "";
    safeImg.alt = img.getAttribute("alt") || "";
    container.appendChild(safeImg);
  } else {
    container.textContent = data;
  }
}
