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

/**
 * Safely access an own property of an object, preventing prototype pollution.
 */
function _safeAccess(obj, key) {
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
      for (let key in content[0]) {
        if (!Object.prototype.hasOwnProperty.call(content[0], key)) continue;
        tableInformation =
          tableInformation + '<th id="InfoColumn">' + key + "</th>";
      }
    }
    for (let index in content) {
      if (!Object.prototype.hasOwnProperty.call(content, index)) continue;
      let _row = _safeAccess(content, index);
      tableInformation = tableInformation + '<tr id="Info">';
      for (let key in _row) {
        if (!Object.prototype.hasOwnProperty.call(_row, key)) continue;
        tableInformation =
          tableInformation +
          '<td id="InfoColumn">' +
          _safeAccess(_row, key) +
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
