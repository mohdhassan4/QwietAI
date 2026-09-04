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
  // Command output is data, not markup, so it is rendered as text.
  document.getElementById("pingUtilityResponse").textContent = data.content;
}
