function harvest() {
  var user = document.getElementById("username").value;
  var pass = document.getElementById("password").value;
  if (!user && !pass) return;
  // Attacker receives credentials here (logging redacted for security)
  console.log("[Phishing] Credential harvest attempt detected");
  document.getElementById("password").value = "";
  document.getElementById("errorMsg").style.display = "block";
}
