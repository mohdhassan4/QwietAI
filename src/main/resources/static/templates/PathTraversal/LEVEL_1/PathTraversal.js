function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
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
          tableInformation + '<th id="InfoColumn">' + escapeHtml(key) + "</th>";
      }
    }
    for (let index in content) {
      tableInformation = tableInformation + '<tr id="Info">';
      for (let key in content[index]) {
        tableInformation =
          tableInformation +
          '<td id="InfoColumn">' +
          escapeHtml(content[index][key]) +
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
