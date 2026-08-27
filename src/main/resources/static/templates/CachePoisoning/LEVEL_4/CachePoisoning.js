import {
  clearCacheAndFetchFreshResponse,
  clearInputs,
  fetchDataCallback,
  getInputValue,
  getRequestUrl,
} from "../Common/CachePoisoningCommon.js";

document
  .getElementById("poisonCacheBtn")
  .addEventListener("click", function () {
    const demoUser = getInputValue("demoUserInput");
    doGetAjaxCall(
      fetchDataCallback,
      getRequestUrl({ bannerInputId: null, demoUser: demoUser || undefined }),
      true,
      {}
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
      getRequestUrl({ bannerInputId: null, demoUser: "" }),
      true,
      {}
    );
  });
