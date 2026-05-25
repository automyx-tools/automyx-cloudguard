/* ==========================================================================
   AutoMyx CloudGuard Web UI Logic
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
  
  // --- STATE ---
  let activeScanData = null;
  let activeCategoryFilter = "all";
  let activeSeverityFilter = "ALL";

  // --- DOM ELEMENTS ---
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");
  
  // Configuration / Scanner elements
  const scanConfigForm = document.getElementById("scan-config-form");
  const startScanBtn = document.getElementById("start-scan-btn");
  const consoleOutput = document.getElementById("console-output");
  const clearConsoleBtn = document.getElementById("clear-console-btn");
  const dropzone = document.getElementById("dropzone");
  const reportFileInput = document.getElementById("report-file-input");

  // Region Search elements
  const regionSearchInput = document.getElementById("aws-region-search");
  const regionHiddenInput = document.getElementById("aws-region");
  const regionDropdown = document.getElementById("aws-region-dropdown");
  const regionOptions = document.querySelectorAll(".region-option");
  
  // System indicator elements
  const engineModeIndicator = document.getElementById("engine-mode");
  const statusIndicator = document.querySelector(".status-indicator");
  const navDashboard = document.getElementById("nav-dashboard");
  const downloadDashboardPdfBtn = document.getElementById("download-dashboard-pdf-btn");

  // Dashboard elements
  const resAccountID = document.getElementById("res-account-id");
  const resRegion = document.getElementById("res-region");
  const resScanMode = document.getElementById("res-scan-mode");
  const resScanTime = document.getElementById("res-scan-time");
  
  const scoreRing = document.getElementById("score-ring");
  const scorePercentage = document.getElementById("score-percentage");
  const scoreRatingText = document.getElementById("score-rating-text");
  
  const metricSavings = document.getElementById("metric-savings");
  const metricChecked = document.getElementById("metric-checked");
  const metricResourceSubtext = document.getElementById("metric-resource-subtext");
  const metricServicesScanned = document.getElementById("metric-services-scanned");
  const metricServicesDeployed = document.getElementById("metric-services-deployed");
  
  const countCritical = document.getElementById("count-critical");
  const countHigh = document.getElementById("count-high");
  const countMedium = document.getElementById("count-medium");
  const countLow = document.getElementById("count-low");
  
  const barCritical = document.getElementById("bar-critical");
  const barHigh = document.getElementById("bar-high");
  const barMedium = document.getElementById("bar-medium");
  const barLow = document.getElementById("bar-low");

  const findingsContainer = document.getElementById("findings-container");
  const categoryFilters = document.querySelectorAll(".filter-toggle-btn");
  const severityFilterSelect = document.getElementById("severity-filter");
  const resourcesContainer = document.getElementById("resources-container");
  const resourceServiceFilter = document.getElementById("resource-service-filter");

  // AI elements
  const aiContextAccount = document.getElementById("ai-context-account");
  const aiContextScore = document.getElementById("ai-context-score");
  const aiContextFindings = document.getElementById("ai-context-findings");
  const aiProviderSelect = document.getElementById("ai-provider-select");
  const aiKeyGroup = document.getElementById("ai-key-group");
  const chatMessagesBox = document.getElementById("chat-messages-box");
  const chatInputForm = document.getElementById("chat-input-form");
  const chatUserInput = document.getElementById("chat-user-input");

  // Toast
  const toastCard = document.getElementById("toast-notification");
  const toastMessage = document.getElementById("toast-message");

  // --- INITIALIZATION ---
  const defaultSimulationReport = runSimulationScanData(); // Demo-only scan data, never a live account scan

  // --- TAB NAVIGATION ---
  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      if (btn.hasAttribute("disabled")) return;
      
      const target = btn.getAttribute("data-target");
      
      // Toggle button states
      tabButtons.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      
      // Toggle content visibility
      tabContents.forEach(content => {
        if (content.id === target) {
          content.classList.add("active-content");
        } else {
          content.classList.remove("active-content");
        }
      });
    });
  });

  // --- SEARCHABLE REGION DROPDOWN ---
  regionSearchInput.addEventListener("click", () => {
    regionDropdown.classList.remove("hidden");
    filterRegions();
  });

  regionSearchInput.addEventListener("input", () => {
    regionDropdown.classList.remove("hidden");
    filterRegions();
  });

  function filterRegions() {
    const text = regionSearchInput.value.toLowerCase().trim();
    regionOptions.forEach(opt => {
      const val = opt.getAttribute("data-value").toLowerCase();
      const txt = opt.textContent.toLowerCase();
      if (val.includes(text) || txt.includes(text)) {
        opt.style.display = "block";
      } else {
        opt.style.display = "none";
      }
    });
  }

  regionOptions.forEach(opt => {
    opt.addEventListener("click", () => {
      const value = opt.getAttribute("data-value");
      
      regionSearchInput.value = value;
      regionHiddenInput.value = value;

      regionOptions.forEach(o => o.classList.remove("selected"));
      opt.classList.add("selected");

      regionDropdown.classList.add("hidden");
    });
  });

  document.addEventListener("click", (e) => {
    if (!e.target.closest(".region-search-container")) {
      regionDropdown.classList.add("hidden");
    }
  });

  // Switch Provider showing API key field if OpenAI chosen
  aiProviderSelect.addEventListener("change", (e) => {
    if (e.target.value === "openai") {
      aiKeyGroup.style.display = "flex";
    } else {
      aiKeyGroup.style.display = "none";
    }
  });

  // --- TOAST NOTIFICATIONS ---
  function showToast(message) {
    toastMessage.textContent = message;
    toastCard.classList.add("show");
    setTimeout(() => {
      toastCard.classList.remove("show");
    }, 3000);
  }

  // --- TERMINAL LOGGER ---
  function clearConsole() {
    consoleOutput.innerHTML = `<div class="console-line system-line">[SYSTEM] Terminal logs cleared. Ready for new scanning operation.</div><div class="console-line prompt-line">$ _</div>`;
  }
  
  clearConsoleBtn.addEventListener("click", clearConsole);

  function logToConsole(message, type = "info") {
    const promptLine = consoleOutput.querySelector(".prompt-line");
    if (promptLine) {
      promptLine.remove();
    }
    
    const timestamp = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.className = `console-line ${type}-line`;
    line.innerHTML = `<span style="color: var(--text-muted)">[${timestamp}]</span> ${message}`;
    
    consoleOutput.appendChild(line);
    
    // Append a new prompt line
    const nextPrompt = document.createElement("div");
    nextPrompt.className = "console-line prompt-line";
    nextPrompt.innerHTML = "$ _";
    consoleOutput.appendChild(nextPrompt);
    
    // Auto Scroll to bottom
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
  }

  // --- CLI-FIRST SCAN FLOW ---
  scanConfigForm.addEventListener("submit", (e) => {
    e.preventDefault();
    clearConsole();
    logToConsole("[BLOCKED] Browser-based AWS credential scans are disabled.", "fail");
    logToConsole("Run the local Go CLI scanner, then drag automyx-report.json into this page.", "info");
    logToConsole("Live scan: ./automyx-cloudguard --output automyx-report.json", "system");
    logToConsole("Demo report: ./automyx-cloudguard --demo --output automyx-demo-report.json", "system");
    showToast("Run the CLI scanner and import automyx-report.json.");
    return;
    
    const accessKey = document.getElementById("aws-access-key").value.trim();
    const secretKey = document.getElementById("aws-secret-key").value.trim();
    const region = document.getElementById("aws-region").value;
    
    startScanBtn.disabled = true;
    startScanBtn.style.opacity = 0.6;
    
    statusIndicator.className = "status-indicator scanning";
    engineModeIndicator.textContent = "SCANNING ACCOUNT...";
    
    clearConsole();
    logToConsole("Initializing client-side Web Auditor Engine...", "system");
    
    const isMock = !accessKey || !secretKey;
    
    if (isMock) {
      logToConsole("[DEMO] Browser scanning is disabled. Import a CLI report instead.", "warn");
    } else {
      logToConsole(`AWS Access Key identified. Target Region: ${region}`, "info");
      logToConsole("Verifying credential permissions via sts:GetCallerIdentity...", "info");
    }
    
    // Simulated sequence of scanning events
    const scanSteps = [
      { delay: 1000, msg: "STS Authentication verified. Session active.", type: "success" },
      { delay: 1800, msg: "Auditing IAM (Identity & Access Management)...", type: "info" },
      { delay: 2400, msg: "IAM Audit: Found 14 active users and 9 roles.", type: "info" },
      { delay: 3000, msg: "[DEMO] Root MFA sample finding loaded.", type: "fail" },
      { delay: 3500, msg: "[DEMO] Stale access key sample finding loaded.", type: "warn" },
      { delay: 4200, msg: "Auditing S3 Storage Buckets for public access blocks...", type: "info" },
      { delay: 4800, msg: "S3 Audit: Found 6 storage buckets in target region.", type: "info" },
      { delay: 5400, msg: "[DEMO] S3 public-access-control sample finding loaded.", type: "warn" },
      { delay: 6000, msg: "Auditing EC2 Network Security Groups & firewalls...", type: "info" },
      { delay: 6800, msg: "[DEMO] Exposed SSH sample finding loaded for sg-demo000000000000.", type: "fail" },
      { delay: 7200, msg: "Auditing EC2 Block Storage (EBS) Volumes for idle waste...", type: "info" },
      { delay: 7800, msg: "💰 [SAVINGS] Found unattached EBS volume 'vol-0a991ee74bc9381c' (Potential Savings: $20.00/mo)", type: "success" },
      { delay: 8400, msg: "💰 [SAVINGS] Found idle VPC NAT Gateway 'nat-02a831eefc678a9' (Potential Savings: $32.40/mo)", type: "success" },
      { delay: 9000, msg: "Scan compilation complete. Generating dashboard matrices...", "type": "system" }
    ];
    
    scanSteps.forEach(step => {
      setTimeout(() => {
        logToConsole(step.msg, step.type);
      }, step.delay);
    });
    
    // Complete Scan
    setTimeout(() => {
      startScanBtn.disabled = false;
      startScanBtn.style.opacity = 1;
      
      statusIndicator.className = "status-indicator online";
      engineModeIndicator.textContent = isMock ? "CLIENT-SIDE (SIMULATION)" : "CLIENT-SIDE (LIVE)";
      
      activeScanData = defaultSimulationReport;
      if (!isMock) {
        // Adjust metadata slightly to indicate live simulation
        activeScanData.scan_metadata.mode = "DEMO";
        activeScanData.scan_metadata.aws_region = region;
        activeScanData.scan_metadata.aws_account_id = "000000000000";
      }
      
      loadDashboardData(activeScanData);
      showToast("AWS scan completed. Executive dashboard loaded!");
      
      // Switch tab to Dashboard
      navDashboard.removeAttribute("disabled");
      navDashboard.click();
      
    }, 9800);
  });

  // --- CLI REPORT FILE IMPORT ---
  // Prevent browser default file open behavior
  ["dragenter", "dragover", "dragleave", "drop"].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
    }, false);
  });

  // Toggle dropzone hover states
  ["dragenter", "dragover"].forEach(eventName => {
    dropzone.addEventListener(eventName, () => dropzone.classList.add("dragover"), false);
  });
  ["dragleave", "drop"].forEach(eventName => {
    dropzone.addEventListener(eventName, () => dropzone.classList.remove("dragover"), false);
  });

  // Handle dropped files
  dropzone.addEventListener("drop", (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleReportFile(files[0]);
    }
  });

  // Handle input browse picker
  reportFileInput.addEventListener("change", (e) => {
    const files = e.target.files;
    if (files.length > 0) {
      handleReportFile(files[0]);
    }
  });

  function handleReportFile(file) {
    if (file.type !== "application/json" && !file.name.endsWith(".json")) {
      logToConsole(`[-] Error: File '${file.name}' is not a valid JSON report.`, "fail");
      showToast("Invalid file type. Please upload a JSON file.");
      return;
    }

    logToConsole(`[+] Local report upload started: ${file.name}`, "system");
    const reader = new FileReader();
    
    reader.onload = (e) => {
      try {
        const report = JSON.parse(e.target.result);
        
        // Basic schema verification
        if (!report.scan_metadata || !report.summary || !("findings" in report)) {
          logToConsole("[-] Error: Uploaded JSON lacks AutoMyx CloudGuard metadata schema.", "fail");
          showToast("Failed to parse report: Invalid format.");
          return;
        }
        if (!Array.isArray(report.findings)) {
          report.findings = [];
        }
        if (!Array.isArray(report.scanned_resources)) {
          report.scanned_resources = [];
        }
        
        logToConsole(`[+] Successfully verified '${file.name}'.`, "success");
        logToConsole(`[+] Mode: ${report.scan_metadata.mode} | Target AWS Account: ${report.scan_metadata.aws_account_id}`, "success");
        logToConsole(`[+] Loaded ${report.findings.length} custom triage security & cost findings.`, "success");
        
        // Set state
        activeScanData = report;
        
        statusIndicator.className = "status-indicator online";
        engineModeIndicator.textContent = `CLI IMPORTED (${report.scan_metadata.mode})`;
        if (downloadDashboardPdfBtn) {
          downloadDashboardPdfBtn.removeAttribute("disabled");
        }
        
        loadDashboardData(activeScanData);
        showToast("Go CLI findings imported successfully!");
        
        // Redirect to dashboard
        navDashboard.removeAttribute("disabled");
        navDashboard.click();
        
      } catch (err) {
        logToConsole(`[-] JSON Parse Error: ${err.message}`, "fail");
        showToast("Error parsing file contents.");
      }
    };
    
    reader.readAsText(file);
  }

  // --- EXECUTIVE DASHBOARD POPULATION ---
  function loadDashboardData(report) {
    // Metadata block
    resAccountID.textContent = report.scan_metadata.aws_account_id;
    resRegion.textContent = report.scan_metadata.aws_region;
    resScanMode.textContent = report.scan_metadata.mode;
    resScanMode.className = `meta-value badge-mode ${report.scan_metadata.mode.includes("LIVE") ? "online" : ""}`;
    resScanTime.textContent = new Date(report.scan_metadata.scan_time).toLocaleString();

    // Summary scores
    const savings = report.summary.cost_savings_monthly;
    metricSavings.textContent = `$${savings.toFixed(2)} / mo`;
    metricChecked.textContent = report.summary.total_checked;
    const resources = Array.isArray(report.scanned_resources) ? report.scanned_resources : [];
    const servicesScanned = Number(report.summary.services_scanned || new Set(resources.map(item => item.service).filter(Boolean)).size || 0);
    const servicesDeployed = Number(report.summary.services_deployed_in_region || countServicesInRegion(resources, report.scan_metadata.aws_region));
    if (metricResourceSubtext) {
      metricResourceSubtext.textContent = `Across ${servicesScanned || "-"} service checks`;
    }
    if (metricServicesScanned) {
      metricServicesScanned.textContent = servicesScanned || "-";
    }
    if (metricServicesDeployed) {
      metricServicesDeployed.textContent = servicesDeployed || "0";
    }

    // Severity badges counts
    countCritical.textContent = report.summary.critical;
    countHigh.textContent = report.summary.high;
    countMedium.textContent = report.summary.medium;
    countLow.textContent = report.summary.low;

    // Calculate percentage rates for severity progress bars
    const totalFlaws = report.summary.total_findings;
    barCritical.style.width = totalFlaws ? `${(report.summary.critical / totalFlaws) * 100}%` : "0%";
    barHigh.style.width = totalFlaws ? `${(report.summary.high / totalFlaws) * 100}%` : "0%";
    barMedium.style.width = totalFlaws ? `${(report.summary.medium / totalFlaws) * 100}%` : "0%";
    barLow.style.width = totalFlaws ? `${(report.summary.low / totalFlaws) * 100}%` : "0%";

    // Compute Security Score percentage
    // Algorithm: Start with 100%. Deduct 15% per critical, 8% per high, 4% per medium, 1% per low. Minimum score: 10%
    let calculatedScore = 100 - (report.summary.critical * 15 + report.summary.high * 8 + report.summary.medium * 4 + report.summary.low * 1);
    calculatedScore = Math.max(10, Math.min(100, calculatedScore));
    
    scorePercentage.textContent = `${calculatedScore}%`;
    
    // Radial gauge rendering stroke offset (circumference of radius 66 circle is 414.69)
    const circumference = 2 * Math.PI * 66;
    const offset = circumference - (calculatedScore / 100) * circumference;
    scoreRing.style.strokeDashoffset = offset;
    
    // Set appropriate styling color/theme based on score
    if (calculatedScore >= 90) {
      scoreRatingText.textContent = "EXCELLENT";
      scoreRatingText.style.color = "var(--success)";
      scoreRing.style.stroke = "var(--success)";
    } else if (calculatedScore >= 70) {
      scoreRatingText.textContent = "NEEDS ATTENTION";
      scoreRatingText.style.color = "var(--high)";
      scoreRing.style.stroke = "var(--high)";
    } else {
      scoreRatingText.textContent = "SEVERE DANGER";
      scoreRatingText.style.color = "var(--critical)";
      scoreRing.style.stroke = "var(--critical)";
    }

    // Load AI panel context variables
    aiContextAccount.textContent = report.scan_metadata.aws_account_id;
    aiContextScore.textContent = `${calculatedScore}%`;
    aiContextScore.className = `context-val ${calculatedScore < 70 ? 'text-critical' : 'text-high'}`;
    aiContextFindings.textContent = report.findings.length;

    // Render finding cards
    renderScannedResources();
    renderFindingCards();
  }

  function countServicesInRegion(resources, region) {
    if (!Array.isArray(resources) || !region) return 0;
    return new Set(resources.filter(item => item.region === region).map(item => item.service).filter(Boolean)).size;
  }

  // --- RENDER SCANNED RESOURCES ---
  function renderScannedResources() {
    if (!activeScanData || !resourcesContainer) return;

    const resources = Array.isArray(activeScanData.scanned_resources) ? activeScanData.scanned_resources : [];
    const services = [...new Set(resources.map(item => item.service).filter(Boolean))].sort();
    const selectedService = resourceServiceFilter ? resourceServiceFilter.value : "ALL";

    if (resourceServiceFilter) {
      const currentValue = resourceServiceFilter.value || "ALL";
      resourceServiceFilter.innerHTML = `<option value="ALL">All Services</option>`;
      services.forEach(service => {
        const option = document.createElement("option");
        option.value = service;
        option.textContent = service;
        resourceServiceFilter.appendChild(option);
      });
      resourceServiceFilter.value = services.includes(currentValue) ? currentValue : "ALL";
    }

    const filteredResources = selectedService === "ALL"
      ? resources
      : resources.filter(item => item.service === selectedService);

    if (filteredResources.length === 0) {
      resourcesContainer.innerHTML = `
        <tr>
          <td colspan="8" class="empty-table-cell">No scanned resources found in this report.</td>
        </tr>
      `;
      return;
    }

    resourcesContainer.innerHTML = filteredResources.map(item => {
      const checks = Array.isArray(item.checks) ? item.checks.join(", ") : "";
      const findingClass = item.finding_count > 0 ? "resource-findings has-findings" : "resource-findings";
      return `
        <tr>
          <td>${escapeHtml(item.service || "-")}</td>
          <td>${escapeHtml(item.resource_type || "-")}</td>
          <td>${escapeHtml(item.name || "-")}</td>
          <td><code>${escapeHtml(item.resource_id || "-")}</code></td>
          <td>${escapeHtml(item.region || "-")}</td>
          <td><span class="resource-status">${escapeHtml(item.status || "-")}</span></td>
          <td>${escapeHtml(checks || "-")}</td>
          <td><span class="${findingClass}">${Number(item.finding_count || 0)}</span></td>
        </tr>
      `;
    }).join("");
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // --- RENDER FINDINGS CARDS ---
  function renderFindingCards() {
    if (!activeScanData) return;
    
    findingsContainer.innerHTML = "";
    
    const filtered = activeScanData.findings.filter(finding => {
      // 1. Filter by category
      const matchCategory = activeCategoryFilter === "all" || finding.category === activeCategoryFilter;
      
      // 2. Filter by severity
      let matchSeverity = true;
      if (activeSeverityFilter !== "ALL") {
        if (activeSeverityFilter === "HIGH") {
          matchSeverity = finding.severity === "CRITICAL" || finding.severity === "HIGH";
        } else if (activeSeverityFilter === "MEDIUM") {
          matchSeverity = finding.severity === "CRITICAL" || finding.severity === "HIGH" || finding.severity === "MEDIUM";
        } else {
          matchSeverity = finding.severity === activeSeverityFilter;
        }
      }
      
      return matchCategory && matchSeverity;
    });

    if (filtered.length === 0) {
      findingsContainer.innerHTML = `
        <div style="text-align: center; padding: 48px; border: 1px dashed var(--border-color); border-radius: 12px; color: var(--text-muted)">
          <svg style="width: 48px; height: 48px; margin-bottom: 12px; opacity: 0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
          <h3>No matching findings discovered</h3>
          <p>Great job! No threats corresponding to these filters were found in your AWS configurations.</p>
        </div>
      `;
      return;
    }

    filtered.forEach(finding => {
      const card = document.createElement("div");
      card.className = "finding-card fade-in";
      
      const severityClass = finding.severity.toLowerCase();
      const categoryIcon = finding.category === "SECURITY" ? "🛡️" : "💰";
      
      card.innerHTML = `
        <div class="finding-title-row">
          <div>
            <div class="finding-meta">
              <span class="finding-service-badge">${finding.service}</span>
              <span class="severity-pill ${severityClass}">${finding.severity}</span>
              <span style="font-size: 0.8rem">${categoryIcon} ${finding.category}</span>
            </div>
            <h3 class="finding-title">${finding.title}</h3>
          </div>
          <span style="font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-muted)">${finding.id}</span>
        </div>
        
        <div class="finding-resource">Resource ID: ${finding.ResourceID || finding.resource_id}</div>
        <p class="finding-desc">${finding.description}</p>
        
        <div class="finding-evidence"><strong>Audit Evidence gathered:</strong>\n${finding.evidence}</div>
        
        ${finding.remediation_cmd ? `
          <div class="finding-remediation">
            <div class="remediation-code"><code>$ ${finding.remediation_cmd}</code></div>
            <button class="copy-btn" data-clipboard="${finding.remediation_cmd}">Copy Command</button>
          </div>
        ` : ''}

        <div class="finding-action-row">
          <button class="btn secondary-btn compact-btn ai-consult-btn" data-finding-id="${finding.id}">
            <span>Consult AI Analyst</span>
            <svg style="width: 14px; height: 14px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
          </button>
        </div>
      `;

      findingsContainer.appendChild(card);
    });

    // Wire up copy events
    findingsContainer.querySelectorAll(".copy-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const textToCopy = btn.getAttribute("data-clipboard");
        navigator.clipboard.writeText(textToCopy).then(() => {
          btn.textContent = "Copied!";
          showToast("CLI remediation command copied to clipboard!");
          setTimeout(() => {
            btn.textContent = "Copy Command";
          }, 2000);
        });
      });
    });

    // Wire up AI Consult trigger buttons
    findingsContainer.querySelectorAll(".ai-consult-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const fId = btn.getAttribute("data-finding-id");
        const findingObj = activeScanData.findings.find(f => f.id === fId);
        if (findingObj) {
          triggerAiConsultation(findingObj);
        }
      });
    });
  }

  // --- FILTERS INTERACTION ---
  categoryFilters.forEach(btn => {
    btn.addEventListener("click", () => {
      categoryFilters.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      activeCategoryFilter = btn.getAttribute("data-category");
      renderFindingCards();
    });
  });

  severityFilterSelect.addEventListener("change", (e) => {
    activeSeverityFilter = e.target.value;
    renderFindingCards();
  });

  if (resourceServiceFilter) {
    resourceServiceFilter.addEventListener("change", renderScannedResources);
  }

  if (downloadDashboardPdfBtn) {
    downloadDashboardPdfBtn.addEventListener("click", () => {
      if (!activeScanData) {
        showToast("Upload a report before exporting the dashboard.");
        return;
      }
      const account = activeScanData.scan_metadata.aws_account_id || "aws-account";
      const region = activeScanData.scan_metadata.aws_region || "region";
      document.title = `AutoMyx-CloudGuard-${account}-${region}`;
      window.print();
      setTimeout(() => {
        document.title = "AutoMyx CloudGuard | AWS Security & Cost Triage";
      }, 500);
    });
  }

  // --- AI SECURITY ANALYST CHAT LOGIC ---
  function appendChatMessage(sender, message) {
    const isAi = sender === "ai";
    const msg = document.createElement("div");
    msg.className = `chat-msg ${isAi ? 'ai-msg' : 'user-msg'} fade-in`;
    
    msg.innerHTML = `
      <div class="msg-bubble">${message}</div>
      <span class="msg-time">${new Date().toLocaleTimeString()}</span>
    `;
    
    chatMessagesBox.appendChild(msg);
    chatMessagesBox.scrollTop = chatMessagesBox.scrollHeight;
  }

  function triggerAiConsultation(finding) {
    // 1. Switch to AI tab
    const aiTabBtn = document.querySelector('[data-target="ai-section"]');
    if (aiTabBtn) aiTabBtn.click();
    
    // 2. Clear user chat input and set context
    chatUserInput.value = "";
    
    // 3. User message
    const prompt = `Can you provide a deep-dive security risk assessment for finding <strong>${finding.id}</strong>: <em>${finding.title}</em>? Please include a complete <strong>Terraform IaC remediation script</strong> to patch this correctly.`;
    appendChatMessage("user", prompt);
    
    // 4. Generate custom AI analysis response
    setTimeout(() => {
      const response = generateMockAiResponse(finding);
      appendChatMessage("ai", response);
    }, 1200);
  }

  chatInputForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const query = chatUserInput.value.trim();
    if (!query) return;
    
    appendChatMessage("user", query);
    chatUserInput.value = "";
    
    setTimeout(() => {
      let aiReply = "I have reviewed your query regarding cloud infrastructure. ";
      
      if (query.toLowerCase().includes("mfa") || query.toLowerCase().includes("root")) {
        aiReply += "Root MFA accounts are critical because IAM root users bypass administrative controls. Make sure to immediately register a hardware key or Virtual Authenticator (Google Authenticator, Duo) via standard AWS CLI or Web Console. Note that root users should not have active CLI credentials.";
      } else if (query.toLowerCase().includes("s3") || query.toLowerCase().includes("public")) {
        aiReply += "Public S3 exposures are generally caused by a mismatch in bucket policy configurations and S3 Public Access Blocks. Enabling the strict Account-Level Public Access Block overrides any relaxed bucket policy. I suggest enforcing default SSE-S3 AES-256 or KMS keys to prevent raw exfiltration.";
      } else if (query.toLowerCase().includes("terraform")) {
        aiReply += "Here is a clean Terraform structure to manage basic AWS resources with strict security defaults:\n\n<pre style=\"background: #020617; border: 1px solid var(--border-color); font-family: var(--font-mono); font-size: 0.775rem; color: #a5f3fc; padding: 14px; border-radius: 8px; margin-top: 10px; overflow-x: auto;\"><code>resource \"aws_s3_bucket\" \"secure_bucket\" {\n  bucket = \"automyx-secure-storage\"\n}\n\nresource \"aws_s3_bucket_public_access_block\" \"block\" {\n  bucket = aws_s3_bucket.secure_bucket.id\n\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}</code></pre>";
      } else {
        aiReply += "As your AutoMyx advisor, I suggest looking through your <strong>Executive Dashboard</strong> to select specific S3, EC2, or IAM flaws. Click 'Consult AI Analyst' on any item, and I will instantly analyze the raw JSON audit trace and build custom security configurations for you.";
      }
      
      appendChatMessage("ai", aiReply);
    }, 1000);
  });

  function generateMockAiResponse(finding) {
    let tfCode = "";
    let riskFactor = "";
    
    if (finding.service === "IAM") {
      riskFactor = "An active, unrotated CLI access key dramatically increases threat vectors. In the event of a laptop compromise, malicious repository pull, or inadvertent local commit containing keys, attackers can scan active keys to hijack administrative power.";
      tfCode = `resource "aws_iam_user" "deployer" {
  name = "dev-deployer"
}

# Enforce secure credentials handling via SSM or IAM Role profiles instead of static key pairs!
# Avoid generating aws_iam_access_key resources directly in static code templates.`;
    } else if (finding.service === "S3") {
      riskFactor = "Bucket policies allowing wildcard Action 's3:GetObject' allow anonymous automated spiders to parse content, compromising sensitive business invoices, database backups, or user configurations.";
      tfCode = `resource "aws_s3_bucket" "invoice_vault" {
  bucket = "automyx-customer-invoice-repository"
}

resource "aws_s3_bucket_public_access_block" "invoice_vault_block" {
  bucket = aws_s3_bucket.invoice_vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`;
    } else if (finding.service === "EC2" || finding.service === "EC2 / Security Groups") {
      riskFactor = "Opening Administrative SSH Port 22 globally targets your servers for automated botnets launching brute-force password spraying. This may trigger excessive processor utilization (denial of service) or active container hijack.";
      tfCode = `resource "aws_security_group" "ssh_restricted" {
  name        = "restrict-ssh-group"
  description = "Restricts ingress traffic exclusively to enterprise IP address blocks"
  vpc_id      = "vpc-0abcde12345"

  ingress {
    description = "SSH access restricted to office gateway"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["198.51.100.0/22"] # Replace with your secure enterprise IP CIDR!
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`;
    } else if (finding.category === "COST") {
      riskFactor = "Idle and unattached cloud elements drain budget margins without adding utility, impacting corporate ROI efficiency metrics.";
      tfCode = `# Orphaned resources must be culled to control budgets.
# Use standard CLI: 'aws ec2 delete-volume --volume-id ${finding.resource_id}' 
# or import them into Terraform state and run 'terraform destroy' to remove them cleanly.`;
    } else {
      riskFactor = "General misconfiguration leading to security compliance failures.";
      tfCode = `# Enforce default secure AWS practices.`;
    }

    return `
      <h4>🛡️ Technical Risk Assessment & Remediation Advisory</h4>
      <p style="margin-top: 8px;"><strong>Finding ID:</strong> ${finding.id}</p>
      <p><strong>Impact Severity:</strong> <span class="text-${finding.severity.toLowerCase()}" style="font-weight: 700">${finding.severity}</span></p>
      
      <div style="margin-top: 14px;">
        <strong>1. Core Threat Analysis:</strong>
        <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 4px;">${riskFactor}</p>
      </div>

      <div style="margin-top: 16px;">
        <strong>2. Evidence Checked locally:</strong>
        <pre style="background: #020617; border: 1px solid var(--border-color); font-family: var(--font-mono); font-size: 0.775rem; color: #38bdf8; padding: 10px; border-radius: 6px; margin-top: 6px; white-space: pre-wrap;"><code>${finding.evidence}</code></pre>
      </div>

      <div style="margin-top: 16px;">
        <strong>3. Standard CLI Remediation:</strong>
        <pre style="background: #020617; border: 1px solid var(--border-color); font-family: var(--font-mono); font-size: 0.775rem; color: #f8fafc; padding: 10px; border-radius: 6px; margin-top: 6px; white-space: pre-wrap;"><code>$ ${finding.remediation_cmd || "Consult Cloud Console"}</code></pre>
      </div>

      <div style="margin-top: 18px;">
        <strong>4. Declarative Infrastructure Fix (Terraform Patch):</strong>
        <p style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 6px;">Integrate this patch into your Terraform repositories to resolve the drift permanently.</p>
        <pre style="background: #020617; border: 1px solid var(--border-color); font-family: var(--font-mono); font-size: 0.75rem; color: #a5f3fc; padding: 14px; border-radius: 8px; overflow-x: auto; line-height: 1.5;"><code>${tfCode}</code></pre>
      </div>
    `;
  }

  // --- MOCK DATABASE FACTORY ---
  function runSimulationScanData() {
    return {
      scan_metadata: {
        tool: "AutoMyx CloudGuard CLI",
        version: "1.1.0",
        scan_time: new Date().toISOString(),
        aws_account_id: "000000000000",
        aws_region: "demo",
        status: "COMPLETED",
        mode: "DEMO"
      },
      summary: {
        total_checked: 124,
        total_findings: 7,
        critical: 2,
        high: 2,
        medium: 2,
        low: 1,
        cost_savings_monthly: 56.00
      },
      findings: [
        {
          id: "DEMO-SEC-IAM-ROOT-MFA",
          service: "IAM",
          category: "SECURITY",
          severity: "CRITICAL",
          title: "[DEMO] Root Account Multi-Factor Authentication (MFA) Missing",
          description: "Simulated finding for dashboard demonstration only.",
          resource_id: "arn:aws:iam::000000000000:root",
          evidence: "DEMO DATA: credential report mfa_active=false.",
          remediation_cmd: "Enable MFA for the root user in the AWS Console.",
          impact: "Demo impact text. Not from a live AWS account."
        },
        {
          id: "DEMO-SEC-EC2-SG",
          service: "EC2 / Security Groups",
          category: "SECURITY",
          severity: "CRITICAL",
          title: "[DEMO] SSH Port Exposed to Public Internet",
          description: "Simulated finding for dashboard demonstration only.",
          resource_id: "sg-demo000000000000",
          evidence: "DEMO DATA: Ingress TCP Port=22 Source=0.0.0.0/0.",
          remediation_cmd: "aws ec2 revoke-security-group-ingress --group-id sg-demo000000000000 --protocol tcp --port 22 --cidr 0.0.0.0/0",
          impact: "Demo impact text. Not from a live AWS account."
        },
        {
          id: "SEC-S3-003",
          service: "S3",
          category: "SECURITY",
          severity: "HIGH",
          title: "S3 Bucket Policy Allows Anonymous Read Access",
          description: "S3 Bucket 'automyx-customer-invoice-repository' allows direct anonymous public read access. Private documents are exposed to search engine crawling.",
          resource_id: "arn:aws:s3:::automyx-customer-invoice-repository",
          evidence: "Bucket Policy contains: Effect: Allow | Principal: * | Action: s3:GetObject",
          remediation_cmd: "aws s3api put-public-access-block --bucket automyx-customer-invoice-repository --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
          impact: "Immediate compliance breach of GDPR/HIPAA. Exposure of private financial invoices to malicious actors."
        },
        {
          id: "COST-NAT-004",
          service: "VPC / NAT Gateway",
          category: "COST",
          severity: "HIGH",
          title: "Idle NAT Gateway Incurring Passive Hourly Fees",
          description: "VPC NAT Gateway 'nat-02a831eefc678a9' is active but has processed less than 5 MB of network throughput over the last 14 days, indicating it is an idle resource.",
          resource_id: "nat-02a831eefc678a9",
          evidence: "CloudWatch NetworkThroughput < 0.01 GB | Active for: 336 hours | Cost: $0.045/hour",
          remediation_cmd: "aws ec2 delete-nat-gateway --nat-gateway-id nat-02a831eefc678a9",
          impact: "Bleeding $32.40 per month in passive AWS rental fees for a completely unused gateway."
        },
        {
          id: "COST-EBS-005",
          service: "EC2 / EBS Volumes",
          category: "COST",
          severity: "MEDIUM",
          title: "Orphaned EBS Hard Disk Volume Active",
          description: "An Elastic Block Store hard disk volume 'vol-0a991ee74bc9381c' is in 'available' state. The hosting EC2 server was terminated weeks ago, but the disk was left orphaned.",
          resource_id: "vol-0a991ee74bc9381c",
          evidence: "Volume State = 'available' | Type = gp3 | Size = 250 GB | Cost: $20.00/month",
          remediation_cmd: "aws ec2 delete-volume --volume-id vol-0a991ee74bc9381c",
          impact: "Wastes $20.00 per month on empty storage blocks that are not connected to any computer."
        },
        {
          id: "SEC-RDS-006",
          service: "RDS / Database",
          category: "SECURITY",
          severity: "MEDIUM",
          title: "Database Instance Lacks Storage Encryption",
          description: "Relational Database (RDS) instance 'automyx-prod-db' (PostgreSQL) has KMS storage encryption disabled. Offline database backups are stored in plaintext.",
          resource_id: "arn:aws:rds:demo:000000000000:db:demo-db",
          evidence: "StorageEncrypted: false",
          remediation_cmd: "No direct CLI fix. Snapshot DB, copy snapshot encrypted, restore snapshot.",
          impact: "Violates basic corporate compliance (SOC2). Threat of database data recovery from physical disk theft or hypervisor compromises."
        },
        {
          id: "COST-EIP-007",
          service: "EC2 / Elastic IP",
          category: "COST",
          severity: "LOW",
          title: "Unattached Elastic IP Address",
          description: "Elastic IP address '54.210.15.89' is reserved in the account but is not associated with any running network interface or EC2 instance. AWS charges an hourly penalty for unused IPs.",
          resource_id: "eipalloc-03c94a557b98d",
          evidence: "Elastic IP: 54.210.15.89 | Association ID: nil | Cost: $0.005/hour",
          remediation_cmd: "aws ec2 release-address --allocation-id eipalloc-03c94a557b98d",
          impact: "Accumulates $3.60 per month in penalty fees for holding an unused public IPv4 address."
        }
      ]
    };
  }
});
