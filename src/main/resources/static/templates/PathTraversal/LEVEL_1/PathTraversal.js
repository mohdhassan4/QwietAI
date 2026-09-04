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
  let information = document.getElementById("Information");
  information.textContent = "";
  if (data.isValid) {
    // The table is built with DOM APIs and every value read from the file is
    // added as text, so the file content can never become markup here.
    let content = JSON.parse(data.content);
    let table = document.createElement("table");
    table.id = "InfoTable";
    if (content.length > 0) {
      let headerRow = document.createElement("tr");
      for (let key in content[0]) {
        let header = document.createElement("th");
        header.id = "InfoColumn";
        header.textContent = key;
        headerRow.appendChild(header);
      }
      table.appendChild(headerRow);
    }
    for (let index in content) {
      let row = document.createElement("tr");
      row.id = "Info";
      for (let key in content[index]) {
        let cell = document.createElement("td");
        cell.id = "InfoColumn";
        cell.textContent = content[index][key];
        row.appendChild(cell);
      }
      table.appendChild(row);
    }
    information.appendChild(table);
  } else {
    information.textContent = "Unable to Load Users";
  }
}
