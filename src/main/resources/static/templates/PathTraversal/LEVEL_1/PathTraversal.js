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

function _safeGet(obj, key) {
  if (obj == null || !Object.prototype.hasOwnProperty.call(obj, key)) {
    return undefined;
  }
  return obj[key];
}

function appendResponseCallback(data) {
  if (data.isValid) {
    let tableInformation = '<table id="InfoTable">';
    let content = JSON.parse(data.content);
    if (content.length > 0) {
      Object.keys(content[0]).forEach(function (key) {
        tableInformation =
          tableInformation + '<th id="InfoColumn">' + key + "</th>";
      });
    }
    Object.keys(content).forEach(function (index) {
      tableInformation = tableInformation + '<tr id="Info">';
      var row = _safeGet(content, index);
      if (row) {
        Object.keys(row).forEach(function (key) {
          tableInformation =
            tableInformation +
            '<td id="InfoColumn">' +
            _safeGet(row, key) +
            "</td>";
        });
      }
      tableInformation = tableInformation + "</tr>";
    });
    tableInformation = tableInformation + "</table>";
    document.getElementById("Information").innerHTML = tableInformation;
  } else {
    document.getElementById("Information").innerHTML = "Unable to Load Users";
  }
}
