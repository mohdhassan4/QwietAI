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
    var content = JSON.parse(data.content);
    var table = document.createElement("table");
    table.id = "InfoTable";

    if (content.length > 0) {
      var headerRow = document.createElement("tr");
      for (var key in content[0]) {
        var th = document.createElement("th");
        th.id = "InfoColumn";
        th.textContent = key;
        headerRow.appendChild(th);
      }
      table.appendChild(headerRow);
    }

    for (var index in content) {
      var row = document.createElement("tr");
      row.id = "Info";
      for (var k in content[index]) {
        var td = document.createElement("td");
        td.id = "InfoColumn";
        td.textContent = content[index][k];
        row.appendChild(td);
      }
      table.appendChild(row);
    }

    var container = document.getElementById("Information");
    container.textContent = "";
    container.appendChild(table);
  } else {
    document.getElementById("Information").textContent = "Unable to Load Users";
  }
}
