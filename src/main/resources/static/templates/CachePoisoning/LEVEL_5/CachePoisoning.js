import {
  clearCacheAndFetchFreshResponse,
  clearInputs,
  fetchDataCallback,
  getHeadersWithForwardedHost,
  getInputValue,
  getRequestUrl,
} from "../Common/CachePoisoningCommon.js";

document
  .getElementById("poisonCacheBtn")
  .addEventListener("click", function () {
    const demoUser = getInputValue("demoUserInput");

    doGetAjaxCall(
      fetchDataCallback,
      getRequestUrl({ demoUser: demoUser || undefined }),
      true,
      getHeadersWithForwardedHost()
    );
    clearInputs(["demoUserInput"]);
  });

document.getElementById("resetCacheBtn").addEventListener("click", function () {
  clearCacheAndFetchFreshResponse();
});

document
  .getElementById("victimRequestBtn")
  .addEventListener("click", function () {
    doGetAjaxCall(
      fetchDataCallback,
      getRequestUrl({ demoUser: "" }),
      true,
      {}
    );
  });
