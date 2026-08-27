function addingEventListenerToPingButton() {
  document.getElementById("pingBtn").addEventListener("click", function () {
    let url = getUrlForVulnerabilityLevel();
    doGetAjaxCall(
      pingUtilityCallback,
      url + "?ipaddress=" + document.getElementById("ipaddress").value,
      true
    );
  });
}
addingEventListenerToPingButton();

function pingUtilityCallback(data) {
  var el = document.getElementById("pingUtilityResponse");
  el.style.whiteSpace = "pre-line";
  el.textContent = data.content;
}
