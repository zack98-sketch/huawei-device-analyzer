/* Front-end logic for the Huawei analyzer web UI.
 *
 * State:
 *   - files:   selected File objects pending upload
 *   - jobData: last /api/analyze response (for tab switching / downloads)
 */
(function () {
  "use strict";

  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("file-input");
  const fileList = document.getElementById("file-list");
  const form = document.getElementById("analyze-form");
  const analyzeBtn = document.getElementById("analyze-btn");
  const statusText = document.getElementById("status-text");
  const logStartInput = document.getElementById("log-start");
  const logEndInput = document.getElementById("log-end");

  const resultsCard = document.getElementById("results-card");
  const errorCard = document.getElementById("error-card");
  const errorDetail = document.getElementById("error-detail");
  const summaryEl = document.getElementById("summary");
  const tabsEl = document.getElementById("result-tabs");
  const tabContent = document.getElementById("tab-content");
  const reportViewer = document.getElementById("report-viewer");
  const viewerActions = document.getElementById("viewer-actions");
  const viewHtmlLink = document.getElementById("view-html");
  const downloadTxtLink = document.getElementById("download-txt");
  const downloadHtmlLink = document.getElementById("download-html");

  let files = [];
  let jobData = null;
  let activeTabIndex = 0;

  // ----- file selection -----
  function setFiles(newFiles) {
    const arr = Array.from(newFiles);
    // de-dupe by name + size
    arr.forEach((f) => {
      if (!files.some((e) => e.name === f.name && e.size === f.size)) {
        files.push(f);
      }
    });
    renderFileList();
    analyzeBtn.disabled = files.length === 0;
  }

  function renderFileList() {
    if (files.length === 0) {
      fileList.classList.add("hidden");
      fileList.innerHTML = "";
      return;
    }
    fileList.classList.remove("hidden");
    fileList.innerHTML = files
      .map(
        (f, i) =>
          `<div class="file-item">
             <span class="fname">${escapeHtml(f.name)} <span class="size">(${formatSize(f.size)})</span></span>
             <button type="button" class="remove" data-i="${i}" title="移除">&times;</button>
           </div>`
      )
      .join("");
    fileList.querySelectorAll(".remove").forEach((b) => {
      b.addEventListener("click", () => {
        const i = parseInt(b.dataset.i, 10);
        files.splice(i, 1);
        renderFileList();
        analyzeBtn.disabled = files.length === 0;
      });
    });
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1024 / 1024).toFixed(1) + " MB";
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );
  }

  // drag & drop
  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer && e.dataTransfer.files) setFiles(e.dataTransfer.files);
  });
  fileInput.addEventListener("change", () => {
    if (fileInput.files) setFiles(fileInput.files);
    fileInput.value = ""; // allow re-selecting the same file
  });

  // ----- analyze -----
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (files.length === 0) return;
    analyzeBtn.disabled = true;
    statusText.className = "status";
    statusText.textContent = "正在上传并分析...";
    errorCard.classList.add("hidden");
    resultsCard.classList.add("hidden");

    const fd = new FormData();
    files.forEach((f) => fd.append("files", f));
    if (logStartInput.value.trim()) fd.append("log_start", logStartInput.value.trim());
    if (logEndInput.value.trim()) fd.append("log_end", logEndInput.value.trim());

    try {
      const resp = await fetch("/api/analyze", { method: "POST", body: fd });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `HTTP ${resp.status}`);
      }
      jobData = data;
      renderSummary(data.summary);
      renderTabs(data);
      statusText.className = "status ok";
      statusText.textContent = `完成: 共分析 ${data.results.length} 个文件`;
      resultsCard.classList.remove("hidden");
    } catch (err) {
      statusText.className = "status error";
      statusText.textContent = "分析失败";
      errorDetail.textContent = String(err.message || err);
      errorCard.classList.remove("hidden");
    } finally {
      analyzeBtn.disabled = false;
    }
  });

  // ----- summary -----
  function renderSummary(s) {
    const avgScore = s.avg_score === null || s.avg_score === undefined
      ? "-"
      : s.avg_score;
    const scoreClass = avgScore === "-" ? "" :
      avgScore >= 90 ? "ok" : avgScore >= 50 ? "medium" : "high";
    summaryEl.innerHTML = `
      <div class="stat"><div class="label">文件总数</div><div class="value">${s.file_count}</div></div>
      <div class="stat"><div class="label">平均合规评分</div><div class="value ${scoreClass}">${avgScore}</div></div>
      <div class="stat"><div class="label">风险项总数</div><div class="value high">${s.total_risks}</div></div>
      <div class="stat"><div class="label">缺失配置项</div><div class="value medium">${s.total_missing}</div></div>
      <div class="stat"><div class="label">日志事件</div><div class="value">${s.total_log_events}</div></div>
      <div class="stat"><div class="label">严重日志事件</div><div class="value high">${s.total_critical_events}</div></div>
    `;
  }

  // ----- tabs -----
  function renderTabs(data) {
    tabsEl.innerHTML = "";
    if (data.batch_stem) {
      const tab = document.createElement("div");
      tab.className = "tab";
      tab.dataset.idx = "-1";
      tab.innerHTML = `批量汇总 <span class="badge">summary</span>`;
      tabsEl.appendChild(tab);
    }
    data.results.forEach((r, i) => {
      const tab = document.createElement("div");
      tab.className = "tab";
      tab.dataset.idx = String(i);
      const score = r.score === null || r.score === undefined ? "-" : r.score;
      const label = `${r.hostname} (${r.device_type})`;
      tab.innerHTML = `${escapeHtml(label)} <span class="badge ${r.device_type}">${
        r.device_type
      }</span>${r.score !== null && r.score !== undefined ? ` <span class="badge">${score}</span>` : ""}`;
      tabsEl.appendChild(tab);
    });
    tabsEl.querySelectorAll(".tab").forEach((t) =>
      t.addEventListener("click", () => activateTab(parseInt(t.dataset.idx, 10)))
    );
    activeTabIndex = data.batch_stem ? -1 : 0;
    activateTab(activeTabIndex);
  }

  function activateTab(idx) {
    activeTabIndex = idx;
    tabsEl.querySelectorAll(".tab").forEach((t) => {
      t.classList.toggle("active", parseInt(t.dataset.idx, 10) === idx);
    });
    if (!jobData) return;
    if (idx === -1 && jobData.batch_stem) {
      loadReport(jobData.job, jobData.batch_stem, "html");
      viewerActions.style.display = "flex";
      viewHtmlLink.href = `/api/batch/${jobData.job}/${jobData.batch_stem}.html`;
      downloadTxtLink.href = `/api/batch/${jobData.job}/${jobData.batch_stem}.txt`;
      downloadHtmlLink.href = `/api/batch/${jobData.job}/${jobData.batch_stem}.html`;
      return;
    }
    const r = jobData.results[idx];
    if (!r) return;
    if (!r.report_stem) {
      reportViewer.innerHTML = `<div class="viewer-placeholder">${
        r.error || "该文件未生成报告"
      }</div>`;
      viewerActions.style.display = "none";
      return;
    }
    loadReport(jobData.job, r.report_stem, "html");
    viewerActions.style.display = "flex";
    viewHtmlLink.href = `/api/report/${jobData.job}/${r.report_stem}.html`;
    downloadTxtLink.href = `/api/report/${jobData.job}/${r.report_stem}.txt`;
    downloadHtmlLink.href = `/api/report/${jobData.job}/${r.report_stem}.html`;
  }

  function loadReport(job, stem, fmt) {
    const url = `/api/report/${job}/${stem}.${fmt}`;
    reportViewer.innerHTML = `<iframe src="${url}" title="report"></iframe>`;
  }
})();
