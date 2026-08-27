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
  var container = document.getElementById("Information");
  container.innerHTML = "";
  if (data.isValid) {
    let content = JSON.parse(data.content);
    var table = document.createElement("table");
    table.id = "InfoTable";
    if (content.length > 0) {
      var headerRow = document.createElement("tr");
      for (let key in content[0]) {
        var th = document.createElement("th");
        th.id = "InfoColumn";
        th.textContent = key;
        headerRow.appendChild(th);
      }
      table.appendChild(headerRow);
    }
    for (let index in content) {
      var row = document.createElement("tr");
      row.id = "Info";
      for (let key in content[index]) {
        var td = document.createElement("td");
        td.id = "InfoColumn";
        td.textContent = content[index][key];
        row.appendChild(td);
      }
      table.appendChild(row);
    }
    container.appendChild(table);
  } else {
    container.textContent = "Unable to Load Users";
  }
}
