/**
 * Safely access an object property by key, preventing prototype pollution
 * attacks via __proto__, constructor, or prototype traversal.
 */
function safeGetPT(obj, key) {
  if (obj == null) return undefined;
  var k = String(key);
  if (k === "__proto__" || k === "constructor" || k === "prototype") {
    return undefined;
  }
  if (!Object.prototype.hasOwnProperty.call(obj, k)) return undefined;
  return obj[k];
}

function addingEventListenerToLoadImageButton() {
  document.getElementById("loadButton").addEventListener("click", function () {
    let url = getUrlForVulnerabilityLevel();
    doGetAjaxCall(
      appendResponseCallback,
      url + "?fileName=" + document.getElementById("fileName").value,
      true
    );
  });
}
addingEventListenerToLoadImageButton();

function appendResponseCallback(data) {
  if (data.isValid) {
    let tableInformation = '<table id="InfoTable">';
    let content = JSON.parse(data.content);
    if (content.length > 0) {
      for (let key in content[0]) {
        tableInformation =
          tableInformation + '<th id="InfoColumn">' + key + "</th>";
      }
    }
    for (let index in content) {
      if (!Object.prototype.hasOwnProperty.call(content, index)) continue;
      tableInformation = tableInformation + '<tr id="Info">';
      let row = safeGetPT(content, index);
      for (let key in row) {
        if (!Object.prototype.hasOwnProperty.call(row, key)) continue;
        tableInformation =
          tableInformation +
          '<td id="InfoColumn">' +
          safeGetPT(row, key) +
          "</td>";
      }
      tableInformation = tableInformation + "</tr>";
    }
    tableInformation = tableInformation + "</table>";
    document.getElementById("Information").innerHTML = tableInformation;
  } else {
    document.getElementById("Information").innerHTML = "Unable to Load Users";
  }
}
