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
      let _row = Object.prototype.hasOwnProperty.call(content, index)
        ? content[index]
        : {};
      tableInformation = tableInformation + '<tr id="Info">';
      for (let key in _row) {
        if (!Object.prototype.hasOwnProperty.call(_row, key)) continue;
        tableInformation =
          tableInformation +
          '<td id="InfoColumn">' +
          (Object.prototype.hasOwnProperty.call(_row, key) ? _row[key] : "") +
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
