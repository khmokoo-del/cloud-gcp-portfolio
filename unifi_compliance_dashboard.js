/**
 * ===================================================================
 * ENTERPRISE - ISO 27001 COMPLIANCE DASHBOARD
 * Automated Infrastructure & Security Posture Ledger
 * Target Controls: 5.9, 7.4, 8.14, 8.20
 * ===================================================================
 */

// ==========================================
// 1. CORE CONFIGURATION & STYLING
// ==========================================
const PROJECT_ID = 'your-gcp-project-id'; 
const BRAND_PRIMARY = "#E86C20";   // Corporate Accent
const BRAND_SECONDARY = "#222222"; // Deep Charcoal Background
const BRAND_TERTIARY = "#333333";  // Header Accent Background
const TEXT_PRIMARY = "#E1E4E6";    // Off-white to prevent halation
const STATUS_ONLINE = "#2D8A4E";   // Desaturated Jade Green
const STATUS_OFFLINE = "#A93226";  // Muted Crimson
const URL_LOGO = "https://your-enterprise-domain.com/dark-theme-logo.png";

// Centralized Region Mapping for Maintainability
const REGION_MAP = {
  "NYC": "North America", "NEW YORK": "North America", "- NA -": "North America",
  "LON": "EMEA", "LONDON": "EMEA", "PARIS": "EMEA", "- EMEA -": "EMEA",
  "TOK": "APAC", "TOKYO": "APAC", "- APAC -": "APAC",
  "SYD": "APAC", "SYDNEY": "APAC",
  "SAO": "LATAM", "SAO PAULO": "LATAM", "- LATAM -": "LATAM"
};

// ==========================================
// 2. USER INTERFACE INITIALIZATION
// ==========================================
function onOpen() {
  const ui = SpreadsheetApp.getUi();
  ui.createMenu('Compliance Ledger')
      .addItem('Run Global Infrastructure Audit', 'runISOAudit')
      .addToUi();
}

function getRegion(consoleName) {
  let upperName = consoleName.toUpperCase();
  for (let key in REGION_MAP) {
    if (upperName.includes(key)) return REGION_MAP[key];
  }
  return "Unknown Region";
}

// ==========================================
// 3. SECURE CREDENTIAL & API MANAGERS
// ==========================================
function getGCPSecret(secretName) {
  const url = `https://secretmanager.googleapis.com/v1/projects/${PROJECT_ID}/secrets/${secretName}/versions/latest:access`;
  try {
    const response = UrlFetchApp.fetch(url, {
      method: 'get',
      headers: { Authorization: `Bearer ${ScriptApp.getOAuthToken()}` },
      muteHttpExceptions: true
    });
    if (response.getResponseCode() === 200) {
      const data = JSON.parse(response.getContentText());
      let rawString = Utilities.newBlob(Utilities.base64Decode(data.payload.data)).getDataAsString();
      return rawString.replace(/[^\x20-\x7E]/g, '').trim();
    }
    throw new Error(`Credential fetch failed. HTTP ${response.getResponseCode()}`);
  } catch (e) {
    console.error(`GCP Secret Manager Error [${secretName}]: ${e.message}`);
    return null;
  }
}

function fetchUniFi(apiKey, baseUrl) {
  const options = { method: 'get', headers: { 'X-API-KEY': apiKey, 'Accept': 'application/json' }, muteHttpExceptions: true };
  let results = [];
  let nextToken = null;
  let retryCount = 0;
  
  try {
    do {
      let url = nextToken 
        ? (baseUrl.includes('?') ? `${baseUrl}&nextToken=${encodeURIComponent(nextToken)}` : `${baseUrl}?nextToken=${encodeURIComponent(nextToken)}`) 
          : baseUrl;
          
      let response = UrlFetchApp.fetch(url, options);
      
      if (response.getResponseCode() === 200) {
        let json = JSON.parse(response.getContentText());
        if (json.data && Array.isArray(json.data)) {
            results = results.concat(json.data);
        }
        nextToken = json.nextToken || null;
        retryCount = 0;
      } else if (response.getResponseCode() === 429) {
        if (retryCount >= 3) {
            console.error(`Rate limit exceeded 3 times at ${url}. Breaking loop.`);
            break;
        }
        retryCount++;
        // PATCH: Implemented Exponential Backoff (2s, 4s, 8s) for resilience
        Utilities.sleep(Math.pow(2, retryCount) * 1000); 
        continue;
      } else {
        console.error(`HTTP ${response.getResponseCode()} at ${url}`);
        break;
      }
    } while (nextToken);
    
    return results;
  } catch (e) {
    console.error(`Data fetch exception at ${baseUrl}: ${e.message}`);
    return results;
  }
}

// ==========================================
// 4. MAIN ORCHESTRATOR
// ==========================================
function runISOAudit() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) return;

  ss.toast("Initiating ISO 27001 Audit Orchestrator. Extracting infrastructure logs...", "Audit Started", 15);

  try {
    const UNIFI_API_KEY = getGCPSecret('CSPM_UNIFI_KEY');
    if (!UNIFI_API_KEY) throw new Error("GCP Secret Fetch Failed. Ensure 'cloud-platform' scope is active.");

    let hosts = fetchUniFi(UNIFI_API_KEY, 'https://api.ui.com/v1/hosts');
    let sites = fetchUniFi(UNIFI_API_KEY, 'https://api.ui.com/v1/sites');
    
    let globalDevices = [];
    if (hosts.length > 0) {
      let devicesRaw = fetchUniFi(UNIFI_API_KEY, 'https://api.ui.com/v1/devices');
      devicesRaw.forEach(hg => {
        if (hg.devices) hg.devices.forEach(d => { d.hostId = hg.hostId || hg.siteId; globalDevices.push(d); });
      });
    }

    let sla24h = buildTrueBusinessContinuity(hosts, sites, 24, globalDevices);
    let sla14d = buildTrueBusinessContinuity(hosts, sites, 336, globalDevices);
    let sla30d = buildTrueBusinessContinuity(hosts, sites, 720, globalDevices);
    
    let postureMatrix = buildPerimeterPosture(hosts, globalDevices, sites);
    let physicalMatrix = buildPhysicalSecurity(hosts, globalDevices, sites);
    let assetMatrix = buildAssetInventory(hosts, globalDevices, sites);

    buildExecutiveDashboard(ss, "Executive Summary", postureMatrix, physicalMatrix, sla30d);
    buildMethodologyCanvas(ss, "ISO Methodology (EN)", getEnglishMethodology());
    buildMethodologyCanvas(ss, "Méthodologie ISO (FR)", getFrenchMethodology());

    buildTab(ss, "Control 8.14: 24-Hour SLA", sla24h, buildSLAFormatting, "Daily Infrastructure Availability (24H).", "Disponibilité quotidienne de l'infrastructure (24H).");
    buildTab(ss, "Control 8.14: 14-Day SLA", sla14d, buildSLAFormatting, "Mid-Term Network Stability Tracking (14D).", "Suivi de la stabilité du réseau à moyen terme (14J).");
    buildTab(ss, "Control 8.14: 30-Day SLA", sla30d, buildSLAFormatting, "Long-Term Availability & Redundancy Validation (30D).", "Validation de la disponibilité et de la redondance à long terme (30J).");
    
    buildTab(ss, "Control 8.20: Operations Posture", postureMatrix, buildActionFormatting, "Perimeter Defense and Threat Scanner Status.", "Défense périmétrique et état des scanners de menaces.");
    buildTab(ss, "Control 7.4: Physical Security", physicalMatrix, buildStatusFormatting, "Surveillance and Environmental Monitoring Status.", "État de la surveillance et du contrôle environnemental.");
    buildTab(ss, "Control 5.9: Inventory", assetMatrix, null, "Global Edge Infrastructure Inventory.", "Inventaire global de l'infrastructure réseau.");

    appendArchiveTab(ss, "Archive: 30-Day SLA History", sla30d, archiveSLAFormatting, "Immutable historical ledger for Business Continuity.", "Registre historique immuable.");
    appendArchiveTab(ss, "Archive: UNVR History", physicalMatrix, archiveStatusFormatting, "Immutable historical ledger for Physical Security.", "Registre historique immuable.");

    const tabOrder = [
      "Executive Summary", "ISO Methodology (EN)", "Méthodologie ISO (FR)", 
      "Control 8.14: 24-Hour SLA", "Control 8.14: 14-Day SLA", "Control 8.14: 30-Day SLA", 
      "Control 8.20: Operations Posture", "Control 7.4: Physical Security", 
      "Control 5.9: Inventory", "Archive: 30-Day SLA History", "Archive: UNVR History"
    ];

    tabOrder.reverse().forEach(name => {
      let t = ss.getSheetByName(name);
      if (t) { ss.setActiveSheet(t); ss.moveActiveSheet(1); }
    });

    ss.toast("ISO 27001 Compliance Dashboard updated successfully.", "Success", 5);
  } catch (error) {
    console.error(`Execution Fault: ${error.stack}`);
    SpreadsheetApp.getUi().alert(`Audit Failed: ${error.message}`);
  }
}

// ==========================================
// 5. COMPLIANCE ENGINES & SLA ALGORITHMS
// ==========================================
function formatUptime(seconds) {
  if (!seconds || seconds <= 0 || isNaN(seconds)) return "OFFLINE";
  let w = Math.floor(seconds / 604800);
  let d = Math.floor((seconds % 604800) / 86400);
  let h = Math.floor((seconds % 86400) / 3600);
  let m = Math.floor((seconds % 3600) / 60);
  let parts = [];
  if (w > 0) parts.push(w + "w");
  if (d > 0) parts.push(d + "d");
  if (h > 0) parts.push(h + "h");
  if (m > 0) parts.push(m + "m");
  return parts.join(" ") || "< 1m";
}

// PATCH: Chronological logic mapping to output raw intervals
function getDowntimeIntervals(issuesArray, windowCutoff) {
  if (!issuesArray || !Array.isArray(issuesArray)) return [];
  let intervals = [];
  issuesArray.forEach(issue => {
    if (issue.wanDowntime || issue.wan_downtime || issue.notReported || issue.not_reported) {
      // NOTE: index represents 5-minute epochs (300,000 ms) in UniFi API
      let startMs = issue.index * 300000; 
      let count = issue.count || 1;
      let endMs = startMs + (count * 300000);

      if (endMs > windowCutoff) {
        let overlapStart = Math.max(startMs, windowCutoff);
        intervals.push({ start: overlapStart, end: endMs });
      }
    }
  });
  return intervals;
}

// PATCH: Flattens overlapping time blocks
function mergeIntervals(intervals) {
  if (!intervals || intervals.length === 0) return [];
  intervals.sort((a,b) => a.start - b.start);
  let merged = [intervals[0]];
  for(let i=1; i<intervals.length; i++) {
     let prev = merged[merged.length-1];
     let curr = intervals[i];
     if(curr.start <= prev.end) {
        prev.end = Math.max(prev.end, curr.end);
     } else {
        merged.push(curr);
     }
  }
  return merged;
}

// PATCH: Finds the exact chronological overlap (intersection) of two interval arrays
function intersectIntervals(arr1, arr2) {
  let i = 0, j = 0;
  let result = [];
  while(i < arr1.length && j < arr2.length) {
     let a = arr1[i], b = arr2[j];
     let startMax = Math.max(a.start, b.start);
     let endMin = Math.min(a.end, b.end);
     
     if (startMax < endMin) result.push({start: startMax, end: endMin});
     
     if (a.end < b.end) i++;
     else j++;
  }
  return result;
}

// PATCH: Converts an array of intervals into exact minutes
function calculateTotalMinutes(intervals) {
  let mins = 0;
  let merged = mergeIntervals(intervals);
  merged.forEach(iv => {
    mins += Math.round((iv.end - iv.start) / 60000);
  });
  return mins;
}

function buildTrueBusinessContinuity(hosts, sites, windowHours, globalDevices) {
  let matrix = [["Region", "Console Identity", "System Uptime", "Primary ISP Performance", "Secondary ISP Performance", "Period", "Site Downtime Minutes", "True Availability Percent"]];
  let now = new Date().getTime();
  let totalMinutes = windowHours * 60;
  let fleetTotalMinutes = 0; 
  let periodString = windowHours === 24 ? "Last 24 Hours" : (windowHours === 336 ? "Last 14 Days" : "Last 30 Days");
  let windowCutoff = now - (windowHours * 60 * 60 * 1000);

  let siteWansMap = {};
  sites.forEach(s => {
    if (s.hostId) {
      let stats = s.statistics || {};
      let wans = stats.wans || {};
      siteWansMap[s.hostId] = {
        primaryName: wans.WAN?.ispInfo?.name || stats.ispInfo?.name || null,
        secondaryName: wans.WAN2?.ispInfo?.name || null,
        primaryIp: wans.WAN?.externalIp || null,
        secondaryIp: wans.WAN2?.externalIp || null,
        primaryIssues: wans.WAN?.wanIssues || null,
        secondaryIssues: wans.WAN2?.wanIssues || null
      };
    }
  });

  hosts.forEach(host => {
    let typeCheck = String((host.name || "") + " " + (host.reportedState?.name || "") + " " + (host.hardware?.shortname || "") + " " + (host.hardware?.name || "")).toUpperCase();
    if (typeCheck.includes("UNVR") || typeCheck.includes("UCK") || typeCheck.includes("NVR")) return; 

    let consoleId = host.id;
    let siteMatch = sites.find(s => s.hostId === consoleId);
    let mappedSiteName = siteMatch?.meta?.desc || siteMatch?.meta?.name;
    let fallbackName = host.name || host.reportedState?.name || `Console_${consoleId.substring(0,6)}`;
    let consoleName = (mappedSiteName && mappedSiteName.toLowerCase() !== "default") ? mappedSiteName : fallbackName;
    
    let region = getRegion(consoleName); // PATCH: Centralized Map Call
    let gateway = globalDevices.find(d => d.hostId === consoleId && d.isConsole === true) || host;
    let gatewayModel = gateway.model || gateway.shortname || host.hardware?.shortname || "Gateway";
    let consoleDisplay = `${consoleName}\n[${gatewayModel}]`;

    let rawStatus = String(gateway.reportedState?.state || gateway.reportedState?.status || gateway.state || gateway.status || host.reportedState?.state || host.reportedState?.status || host.state || host.status || "UNKNOWN").toUpperCase();
    let isOnline = false;
    if (rawStatus.includes("DISCONNECTED") || rawStatus.includes("OFFLINE")) {
        isOnline = false;
    } else if (["ONLINE", "CONNECTED", "ACTIVE", "TRUE", "1", "DEGRADED", "WARNING", "ATTENTION"].some(s => rawStatus.includes(s))) {
        isOnline = true;
    }

    let startupTime = gateway.startupTime || host.reportedState?.startupTime;
    let upSecs = startupTime ? Math.floor((now - new Date(startupTime).getTime()) / 1000) : parseInt(gateway.uptime || host.reportedState?.uptime || 0);
    let uptimeStr = formatUptime(upSecs);

    let wansInfo = siteWansMap[consoleId] || { primaryName: null, secondaryName: null, primaryIp: null, secondaryIp: null, primaryIssues: null, secondaryIssues: null };
    let hardWan2 = host.reportedState?.wans?.find(w => w.type === 'WAN2' || w.type === 'WAN_2');
    
    let hasWan2Name = !!(wansInfo.secondaryName && wansInfo.secondaryName.trim() !== "");
    let hasWan2Ip = !!(wansInfo.secondaryIp && wansInfo.secondaryIp !== "0.0.0.0");
    let hasHardWan2Ip = !!(hardWan2?.ipv4 && hardWan2.ipv4 !== "0.0.0.0");
    let hasWan2 = hasWan2Name || hasWan2Ip || hasHardWan2Ip;

    let wan1Ip = host.reportedState?.wans?.find(w => w.type === 'WAN')?.ipv4 || gateway.wanIp;
    let wan2Ip = hardWan2?.ipv4 || wansInfo.secondaryIp;

    let isp1 = wansInfo.primaryName || (wansInfo.primaryIp ? `IP: ${wansInfo.primaryIp}` : (wan1Ip ? `IP: ${wan1Ip}` : "Unknown Provider"));
    let isp2 = wansInfo.secondaryName || (wansInfo.secondaryIp ? `IP: ${wansInfo.secondaryIp}` : (wan2Ip && wan2Ip !== "0.0.0.0" ? `IP: ${wan2Ip}` : (hasWan2 ? "Backup Circuit Active" : "-")));
    
    let rawPrimaryIssues = wansInfo.primaryIssues || host.reportedState?.internetIssues5min?.periods || host.internetIssues5min?.periods || [];
    let rawSecondaryIssues = wansInfo.secondaryIssues || [];

    // PATCH: Extract absolute true downtime using interval intersections
    let primaryIntervals = getDowntimeIntervals(rawPrimaryIssues, windowCutoff);
    let primaryDowntime = calculateTotalMinutes(primaryIntervals);
    
    let secondaryIntervals = hasWan2 ? getDowntimeIntervals(rawSecondaryIssues, windowCutoff) : [];
    let secondaryDowntime = hasWan2 ? calculateTotalMinutes(secondaryIntervals) : 0;
    
    let totalSiteOffline = 0; 

    if (!isOnline) {
        totalSiteOffline = totalMinutes; 
        primaryDowntime = totalMinutes;
        if (hasWan2) secondaryDowntime = totalMinutes;
    } else {
        if (hasWan2) {
            let concurrentIntervals = intersectIntervals(mergeIntervals(primaryIntervals), mergeIntervals(secondaryIntervals));
            totalSiteOffline = calculateTotalMinutes(concurrentIntervals);
        } else {
            totalSiteOffline = primaryDowntime;
        }
        
        totalSiteOffline = Math.min(totalSiteOffline, totalMinutes);
        primaryDowntime = Math.min(primaryDowntime, totalMinutes);
        secondaryDowntime = Math.min(secondaryDowntime, totalMinutes);
    }

    fleetTotalMinutes += totalSiteOffline;
    
    let truePct = totalSiteOffline === totalMinutes ? "OFFLINE" : (((totalMinutes - totalSiteOffline) / totalMinutes) * 100).toFixed(2) + "%";
    let p1Pct = totalSiteOffline === totalMinutes ? "OFFLINE" : (((totalMinutes - primaryDowntime) / totalMinutes) * 100).toFixed(2) + "%";
    let p2Pct = hasWan2 ? (totalSiteOffline === totalMinutes ? "OFFLINE" : (((totalMinutes - secondaryDowntime) / totalMinutes) * 100).toFixed(2) + "%") : "N/A";

    let p1String = `${isp1}\n(${primaryDowntime}m Down | ${p1Pct})`;
    let p2String = hasWan2 ? `${isp2}\n(${secondaryDowntime}m Down | ${p2Pct})` : "-";

    matrix.push([region, consoleDisplay, uptimeStr, p1String, p2String, periodString, totalSiteOffline, truePct]);
  });

  let fleetHours = Math.floor(fleetTotalMinutes / 60);
  let fleetRemMins = fleetTotalMinutes % 60;
  matrix.push(["", "", "", "", "", "GLOBAL INFRASTRUCTURE AGGREGATE", `${fleetTotalMinutes}m (${fleetHours}h ${fleetRemMins}m)`, ""]);

  return matrix;
}

function buildPerimeterPosture(hosts, globalDevices, sites) {
  let matrix = [["Console Identity", "Hardware Model", "Firmware Version", "IPS / IDS Status", "Threat Scanner State", "System Uptime"]];
  let now = new Date().getTime(); 
  
  hosts.forEach(h => {
    let typeCheck = String((h.name || "") + " " + (h.reportedState?.name || "") + " " + (h.hardware?.shortname || "") + " " + (h.hardware?.name || "")).toUpperCase();
    if (typeCheck.includes("UNVR") || typeCheck.includes("UCK") || typeCheck.includes("NVR")) return; 

    let consoleId = h.id;
    let siteMatch = sites.find(s => s.hostId === consoleId);
    let mappedSiteName = siteMatch?.meta?.desc || siteMatch?.meta?.name;
    let fallbackName = h.name || h.reportedState?.name || `Console_${consoleId.substring(0,6)}`;
    let consoleName = (mappedSiteName && mappedSiteName.toLowerCase() !== "default") ? mappedSiteName : fallbackName;
    
    let gateway = globalDevices.find(d => d.hostId === consoleId && d.isConsole === true) || h;
    let fw = gateway.version || h.hardware?.firmwareVersion || "Unknown";
    let model = gateway.model || h.hardware?.name || "Gateway Architecture";
    
    let rawStatus = String(gateway.reportedState?.state || gateway.reportedState?.status || gateway.state || gateway.status || h.reportedState?.state || h.reportedState?.status || h.state || h.status || "UNKNOWN").toUpperCase();
    let isOnline = false;
    if (rawStatus.includes("DISCONNECTED") || rawStatus.includes("OFFLINE")) {
        isOnline = false;
    } else if (["ONLINE", "CONNECTED", "ACTIVE", "TRUE", "1", "DEGRADED", "WARNING", "ATTENTION"].some(s => rawStatus.includes(s))) {
        isOnline = true;
    }

    let startupTime = gateway.startupTime || h.reportedState?.startupTime;
    let upSecs = startupTime ? Math.floor((now - new Date(startupTime).getTime()) / 1000) : parseInt(gateway.uptime || h.reportedState?.uptime || 0);
    let uptimeStr = isOnline ? formatUptime(upSecs) : "OFFLINE";

    let ipsMode = "DISABLED";
    let siteData = sites.find(s => s.hostId === consoleId);
    if (siteData && siteData.statistics && siteData.statistics.gateway) {
      ipsMode = String(siteData.statistics.gateway.ipsMode || "DISABLED").toUpperCase();
    } else if (h.reportedState?.ipsMode) {
      ipsMode = String(h.reportedState.ipsMode).toUpperCase();
    }

    let scannerState = (ipsMode === "IPS" || ipsMode === "IDS") ? "Active & Enforced" : "Inactive";
    matrix.push([consoleName, model, fw, ipsMode, scannerState, uptimeStr]);
  });
  return matrix;
}

function buildPhysicalSecurity(hosts, globalDevices, sites) {
  let matrix = [["Region", "Console Identity", "Hardware Model", "Firmware Version", "System Uptime", "Connection Status"]];
  let now = new Date().getTime(); 
  
  hosts.forEach(h => {
    let typeCheck = String((h.name || "") + " " + (h.reportedState?.name || "") + " " + (h.hardware?.shortname || "") + " " + (h.hardware?.name || "")).toUpperCase();
    if (!(typeCheck.includes("UNVR") || typeCheck.includes("UCK") || typeCheck.includes("NVR"))) return; 

    let consoleId = h.id;
    let siteMatch = sites.find(s => s.hostId === consoleId);
    let mappedSiteName = siteMatch?.meta?.desc || siteMatch?.meta?.name;
    let fallbackName = h.name || h.reportedState?.name || `Console_${consoleId.substring(0,6)}`;
    let consoleName = (mappedSiteName && mappedSiteName.toLowerCase() !== "default") ? mappedSiteName : fallbackName;
    
    let region = getRegion(consoleName); // PATCH: Centralized Map Call
    let nvr = globalDevices.find(d => d.hostId === consoleId && d.isConsole === true) || h;
    let model = nvr.model || nvr.shortname || h.hardware?.shortname || h.hardware?.name || "UNVR Architecture";
    let consoleDisplay = `${consoleName}\n[${model}]`;
    let fw = nvr.version || h.hardware?.firmwareVersion || "Unknown";
    
    let rawStatus = String(nvr.reportedState?.state || nvr.reportedState?.status || nvr.state || nvr.status || h.reportedState?.state || h.reportedState?.status || h.state || h.status || "UNKNOWN").toUpperCase();
    let isOnline = false;
    if (rawStatus.includes("DISCONNECTED") || rawStatus.includes("OFFLINE")) {
        isOnline = false;
    } else if (["ONLINE", "CONNECTED", "ACTIVE", "TRUE", "1", "DEGRADED", "WARNING", "ATTENTION"].some(s => rawStatus.includes(s))) {
        isOnline = true;
    }

    let startupTime = nvr.startupTime || h.reportedState?.startupTime;
    let upSecs = startupTime ? Math.floor((now - new Date(startupTime).getTime()) / 1000) : parseInt(nvr.uptime || h.reportedState?.uptime || 0);
    let uptimeStr = formatUptime(upSecs);
    let displayStatus = isOnline ? "ONLINE" : "OFFLINE";

    matrix.push([region, consoleDisplay, model, fw, uptimeStr, displayStatus]);
  });
  return matrix;
}

function buildAssetInventory(hosts, globalDevices, sites) {
  let matrix = [["Console Identity", "Device Name", "Hardware Model", "MAC Address", "Public IP", "Internal IP", "Firmware", "Status"]];
  
  globalDevices.forEach(d => {
    let host = hosts.find(h => h.id === d.hostId || h.id === d.siteId) || {};
    let site = sites.find(s => s.siteId === d.siteId) || sites.find(s => s.hostId === d.hostId) || {};
    
    let mappedSiteName = site.meta?.desc || site.meta?.name || site.name;
    let fallbackName = host.name || host.reportedState?.name || "Unknown Site";
    let consoleName = (mappedSiteName && mappedSiteName.toLowerCase() !== "default") ? mappedSiteName : fallbackName;
    
    let devName = d.name || d.shortname || "Network Device";
    let model = d.model || "Unknown";
    let mac = d.macAddress || d.mac || "-";
    
    let pubIp = "-";
    if (d.isConsole === true || d.type === "GATEWAY") {
        let wans = site.statistics?.wans || {};
        pubIp = wans.WAN?.externalIp || d.wanIp || "-";
    }

    let intIp = d.ipAddress || d.ip || "-";
    let fw = d.firmwareVersion || d.version || "-";
    let status = String(d.state || d.status || "UNKNOWN").toUpperCase();

    matrix.push([consoleName, devName, model, mac, pubIp, intIp, fw, status]);
  });
  return matrix;
}

// ==========================================
// 6. UI RENDERING & DATA LOGGER
// ==========================================
// PATCH: Replaced deletion with sheet.clear() to preserve referencing IDs and avoid #REF! errors
function getCleanSheet(ss, sheetName) {
  let sheet = ss.getSheetByName(sheetName);
  if (sheet) {
    sheet.clear(); 
    sheet.setHiddenGridlines(true); 
    return sheet;
  }
  let newSheet = ss.insertSheet(sheetName);
  newSheet.setHiddenGridlines(true); 
  return newSheet;
}

function buildExecutiveDashboard(ss, sheetName, postureMatrix, physicalMatrix, slaMatrix) {
  let sheet = getCleanSheet(ss, sheetName);
  
  sheet.getRange(1, 1, Math.max(sheet.getMaxRows(), 30), Math.max(sheet.getMaxColumns(), 15)).setBackground(BRAND_SECONDARY);
  
  sheet.getRange(2, 2, 2, 2).merge().setFormula(`=IMAGE("${URL_LOGO}", 1)`);
  sheet.getRange(2, 4, 2, 6).merge().setValue("EXECUTIVE MANAGEMENT DASHBOARD").setFontSize(16).setFontWeight("bold").setFontColor(BRAND_PRIMARY).setVerticalAlignment("middle");
  sheet.getRange(4, 4, 1, 6).merge().setValue("ISO 27001:2022 - Clause 9.3: Management Review").setFontStyle("italic").setFontColor(TEXT_PRIMARY);
  
  let totalGateways = Math.max(postureMatrix.length - 1, 0);
  let onlineGateways = totalGateways > 0 ? postureMatrix.slice(1).filter(r => !String(r[5]).includes("OFFLINE")).length : 0;
  
  let totalUNVRs = Math.max(physicalMatrix.length - 1, 0);
  let onlineUNVRs = totalUNVRs > 0 ? physicalMatrix.slice(1).filter(r => String(r[5]) === "ONLINE").length : 0;
  
  let ipsEnforced = totalGateways > 0 ? postureMatrix.slice(1).filter(r => String(r[4]).includes("Active")).length : 0;
  let ipsPct = totalGateways > 0 ? Math.round((ipsEnforced / totalGateways) * 100) : 0;
  
  let slaData = slaMatrix.length > 2 ? slaMatrix.slice(1, -1) : []; 
  let totalMins = 720 * 60; 
  let aggOfflineMins = slaData.reduce((acc, r) => acc + (parseInt(r[6]) || 0), 0);
  let overallUptime = totalGateways > 0 ? (((totalMins * totalGateways) - aggOfflineMins) / (totalMins * totalGateways) * 100).toFixed(2) : 0;

  function drawCard(row, col, title, value, subtext, color) {
    sheet.getRange(row, col, 1, 3).merge().setValue(title).setFontColor(TEXT_PRIMARY).setFontWeight("bold").setBackground(BRAND_TERTIARY).setHorizontalAlignment("center").setBorder(true, true, false, true, false, false, color, SpreadsheetApp.BorderStyle.SOLID_MEDIUM);
    sheet.getRange(row+1, col, 2, 3).merge().setValue(value).setFontColor(color).setFontSize(24).setFontWeight("bold").setBackground(BRAND_TERTIARY).setHorizontalAlignment("center").setVerticalAlignment("middle").setBorder(false, true, false, true, false, false, color, SpreadsheetApp.BorderStyle.SOLID_MEDIUM);
    sheet.getRange(row+3, col, 1, 3).merge().setValue(subtext).setFontColor(TEXT_PRIMARY).setFontSize(9).setBackground(BRAND_TERTIARY).setHorizontalAlignment("center").setBorder(false, true, true, true, false, false, color, SpreadsheetApp.BorderStyle.SOLID_MEDIUM);
  }

  drawCard(7, 2, "NETWORK INFRASTRUCTURE", `${onlineGateways} / ${totalGateways}`, "Gateways Online (Control 8.14)", onlineGateways === totalGateways ? STATUS_ONLINE : STATUS_OFFLINE);
  drawCard(7, 6, "PHYSICAL SECURITY", `${onlineUNVRs} / ${totalUNVRs}`, "UNVRs Online (Control 7.4)", onlineUNVRs === totalUNVRs ? STATUS_ONLINE : STATUS_OFFLINE);
  drawCard(12, 2, "PERIMETER DEFENSE", `${ipsPct}%`, "Threat Scanners Active (Control 8.20)", ipsPct === 100 ? STATUS_ONLINE : STATUS_OFFLINE);
  drawCard(12, 6, "30-DAY RESILIENCE", `${overallUptime}%`, "Global Infrastructure Uptime (Control 8.14)", overallUptime >= 99 ? STATUS_ONLINE : STATUS_OFFLINE);
  
  sheet.setColumnWidth(1, 30); 
  for(let i=2; i<=10; i++) sheet.setColumnWidth(i, 110);
}

function buildMethodologyCanvas(ss, sheetName, contentData) {
  let sheet = getCleanSheet(ss, sheetName);
  sheet.getRange(1, 1, sheet.getMaxRows(), sheet.getMaxColumns()).setBackground(BRAND_SECONDARY);
  sheet.getRange(2, 2, 2, 2).merge().setFormula(`=IMAGE("${URL_LOGO}", 1)`);
  
  let canvas = sheet.getRange("C5:J50");
  canvas.merge();
  canvas.setBackground(BRAND_SECONDARY);
  canvas.setVerticalAlignment("top");
  canvas.setHorizontalAlignment("left");
  canvas.setWrap(true);
  
  let fullText = "";
  contentData.forEach(item => { fullText += item.text + "\n\n"; });
  fullText = fullText.trim();
  
  let richText = SpreadsheetApp.newRichTextValue().setText(fullText);
  let currentIndex = 0;
  
  let headerStyle = SpreadsheetApp.newTextStyle().setForegroundColor(BRAND_PRIMARY).setBold(true).setFontSize(12).build();
  let bodyStyle = SpreadsheetApp.newTextStyle().setForegroundColor(TEXT_PRIMARY).setBold(false).setFontSize(11).build();
  
  contentData.forEach(item => {
    let len = item.text.length;
    if (item.type === "header") {
      richText.setTextStyle(currentIndex, currentIndex + len, headerStyle);
    } else {
      richText.setTextStyle(currentIndex, currentIndex + len, bodyStyle);
    }
    currentIndex += len + 2; 
  });
  
  canvas.setRichTextValue(richText.build());
  sheet.setColumnWidth(1, 30); 
  sheet.setColumnWidth(2, 110); 
  for(let i=3; i<=11; i++) sheet.setColumnWidth(i, 110); 
}

function buildUniversalHeader(sheet, titleText, descEN, descFR, totalCols) {
  let headerCols = Math.max(totalCols, 5); 
  sheet.getRange(1, 1, 5, Math.max(sheet.getMaxColumns(), headerCols)).setBackground(BRAND_SECONDARY);
  sheet.getRange(1, 1, 2, 2).merge().setFormula(`=IMAGE("${URL_LOGO}", 1)`).setBackground(BRAND_SECONDARY);
  sheet.getRange(1, 3, 2, headerCols - 2).merge().setValue(`ISO 27001 AUDIT COMPLIANCE - ${titleText.toUpperCase()}`).setBackground(BRAND_SECONDARY).setFontColor(TEXT_PRIMARY).setFontSize(14).setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.getRange(3, 1, 1, headerCols).merge().setValue(`EN: ${descEN}`).setBackground(BRAND_TERTIARY).setFontColor(TEXT_PRIMARY).setFontStyle("italic").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.getRange(4, 1, 1, headerCols).merge().setValue(`FR: ${descFR}`).setBackground(BRAND_TERTIARY).setFontColor(TEXT_PRIMARY).setFontStyle("italic").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.getRange(5, 1, 1, headerCols).setBackground(BRAND_SECONDARY);
  sheet.getRange(1, 1, 2, headerCols).setBorder(true, true, true, true, false, false, BRAND_PRIMARY, SpreadsheetApp.BorderStyle.SOLID_THICK);
}

function buildTab(ss, sheetName, matrix, formatFn, descEN, descFR) {
  let sheet = getCleanSheet(ss, sheetName);
  let data = (!matrix || matrix.length === 0) ? [["Data", "Status"]] : matrix;
  let totalCols = data[0].length;
  if (data.length === 1) data.push(new Array(totalCols).fill("-"));

  let maxCols = sheet.getMaxColumns();
  let targetCols = Math.max(totalCols, 5); 
  if (maxCols > targetCols) sheet.deleteColumns(targetCols + 1, maxCols - targetCols);
  
  let maxRows = sheet.getMaxRows();
  let targetRows = Math.max(data.length + 6, 20); 
  if (maxRows > targetRows) sheet.deleteRows(targetRows + 1, maxRows - targetRows);

  let dataBodyRange = sheet.getRange(1, 1, sheet.getMaxRows(), sheet.getMaxColumns());
  dataBodyRange.setBackground(BRAND_SECONDARY).setFontColor(TEXT_PRIMARY).setHorizontalAlignment("center").setVerticalAlignment("middle").setWrap(true); 

  sheet.getRange(6, 1, data.length, totalCols).setValues(data);
  sheet.getRange(6, 1, 1, totalCols).setBackground(BRAND_PRIMARY).setFontColor(TEXT_PRIMARY).setFontWeight("bold");
  
  if (data.length > 1 && totalCols >= 2) sheet.getRange(7, 1, data.length - 1, 2).setHorizontalAlignment("left");

  if (formatFn) formatFn(sheet);
  buildUniversalHeader(sheet, sheetName, descEN, descFR, totalCols);
  
  sheet.setFrozenRows(6);
  sheet.autoResizeColumns(1, totalCols);
  for (let i = 1; i <= totalCols; i++) {
    let currentWidth = sheet.getColumnWidth(i);
    sheet.setColumnWidth(i, Math.min(currentWidth + 40, 260)); 
  }
}

function appendArchiveTab(ss, sheetName, matrix, formatFn, descEN, descFR) {
  if (!matrix || matrix.length <= 1) return; 

  let sheet = ss.getSheetByName(sheetName);
  let timestamp = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyyy-MM-dd HH:mm");
  
  let headers = ["Audit Timestamp"].concat(matrix[0]);
  let dataToAppend = [];
  for (let i = 1; i < matrix.length; i++) {
    if (String(matrix[i][1]).includes("GLOBAL INFRASTRUCTURE") || String(matrix[i][5]).includes("GLOBAL INFRASTRUCTURE")) continue;
    dataToAppend.push([timestamp].concat(matrix[i]));
  }
  let totalCols = headers.length;

  if (!sheet) {
    sheet = ss.insertSheet(sheetName);
    sheet.setHiddenGridlines(true);
    let maxCols = sheet.getMaxColumns();
    if (maxCols > totalCols) sheet.deleteColumns(totalCols + 1, maxCols - totalCols);
    
    buildUniversalHeader(sheet, sheetName, descEN, descFR, totalCols);
    
    sheet.getRange(1, 1, sheet.getMaxRows(), sheet.getMaxColumns()).setBackground(BRAND_SECONDARY).setFontColor(TEXT_PRIMARY).setHorizontalAlignment("center").setVerticalAlignment("middle").setWrap(true); 
    sheet.getRange(6, 1, 1, totalCols).setValues([headers]);
    sheet.getRange(6, 1, 1, totalCols).setBackground(BRAND_PRIMARY).setFontColor(TEXT_PRIMARY).setFontWeight("bold");
    sheet.setFrozenRows(6);
    
    sheet.autoResizeColumns(1, totalCols);
    for (let i = 1; i <= totalCols; i++) {
        let currentWidth = sheet.getColumnWidth(i);
        sheet.setColumnWidth(i, Math.min(currentWidth + 40, 260));
    }
  }

  let lastRow = sheet.getLastRow();
  let startRow = Math.max(lastRow + 1, 7);
  
  if (startRow + dataToAppend.length - 1 > sheet.getMaxRows()) {
      sheet.insertRowsAfter(sheet.getMaxRows(), dataToAppend.length + 50);
  }

  sheet.getRange(startRow, 1, dataToAppend.length, totalCols).setValues(dataToAppend).setBackground(BRAND_SECONDARY).setFontColor(TEXT_PRIMARY).setHorizontalAlignment("center").setVerticalAlignment("middle").setWrap(true);
  if (formatFn) formatFn(sheet);
}

// ==========================================
// 7. CONTENT GENERATORS
// ==========================================
function getEnglishMethodology() {
  return [
    { type: "header", text: "ISO 27001 AUDIT COMPLIANCE METHODOLOGY" },
    { type: "header", text: "Scope and Period:" },
    { type: "body", text: "This SLA calculation is based exclusively on hardware logs extracted from the edge infrastructure. The data evaluates rolling 24-hour, 14-day, and 30-day reporting windows to ensure compliance consistency." },
    { type: "header", text: "Data Source:" },
    { type: "body", text: "Automated extraction of WAN connection states, failover events, and device uptime directly from the infrastructure API via GCP Secret Manager integration." },
    { type: "header", text: "Event Normalization:" },
    { type: "body", text: "A site is only classified as offline if both the Primary and Secondary (Backup) circuits experience a concurrent failure. The engine utilizes an interval intersection algorithm to extract strict chronologically overlapping downtime, ensuring absolute precision. Successful failovers to a backup circuit represent High Availability (HA) routing and do not negatively impact the site's overall availability rate." },
    { type: "header", text: "Downtime Minutes:" },
    { type: "body", text: "Calculated using the hardware's internal 5-minute reporting blocks. Outages are mathematically strictly bounded to the reference period (e.g., maximum 1,440 minutes for a 24-hour window) to prevent historical data overlap." },
    { type: "header", text: "Availability Rate:" },
    { type: "body", text: "Calculated as: (Total minutes in reference period − Site Downtime minutes) / Total minutes in reference period × 100." },
    { type: "header", text: "Inclusion Criteria:" },
    { type: "body", text: "Only explicit drops in WAN connectivity validated by hardware logs are included. Idle backup circuits or unconfigured secondary ports are algorithmically excluded to prevent false downtime penalties." },
    { type: "header", text: "Audit Traceability:" },
    { type: "body", text: "All aggregated metrics correspond directly to raw hardware events logged by the network controllers, ensuring full transparency and traceability." }
  ];
}

function getFrenchMethodology() {
  return [
    { type: "header", text: "MÉTHODOLOGIE DE CONFORMITÉ D'AUDIT ISO 27001" },
    { type: "header", text: "Périmètre et Période :" },
    { type: "body", text: "Ce calcul de SLA est basé exclusivement sur les journaux matériels extraits de l'infrastructure réseau. Les données évaluent des périodes glissantes de 24 heures, 14 jours et 30 jours pour garantir la cohérence de la conformité." },
    { type: "header", text: "Source des Données :" },
    { type: "body", text: "Extraction automatisée des états de connexion WAN, des événements de basculement et de la disponibilité des appareils directement depuis l'API d'infrastructure via l'intégration GCP Secret Manager." },
    { type: "header", text: "Normalisation des Événements :" },
    { type: "body", text: "Un site n'est considéré comme hors ligne que si les circuits principal et secondaire (secours) subissent une panne simultanée. Le moteur utilise un algorithme d'intersection d'intervalles pour extraire les temps d'arrêt se chevauchant strictement de manière chronologique, garantissant une précision absolue. Un basculement réussi vers un circuit de secours représente un routage à haute disponibilité (HA) et n'affecte pas le taux de disponibilité global du site." },
    { type: "header", text: "Minutes d'Indisponibilité :" },
    { type: "body", text: "Calculées à l'aide des blocs matériels internes de 5 minutes. Les pannes sont strictement limitées mathématiquement à la période de référence (ex. : maximum 1 440 minutes pour une fenêtre de 24 heures) pour éviter le chevauchement des données historiques." },
    { type: "header", text: "Taux de Disponibilité :" },
    { type: "body", text: "Calculé comme suit : (Total des minutes de la période de référence − Minutes d'indisponibilité du site) / Total des minutes de la période de référence × 100." },
    { type: "header", text: "Critères d'Inclusion :" },
    { type: "body", text: "Seules les pertes explicites de connectivité WAN validées par les journaux matériels sont incluses. Les circuits de secours inactifs ou les ports secondaires non configurés sont exclus de manière algorithmique pour éviter les fausses pénalités." },
    { type: "header", text: "Traçabilité de l'Audit :" },
    { type: "body", text: "Toutes les métriques agrégées correspondent directement aux événements matériels bruts enregistrés par les contrôleurs réseau, garantissant une transparence et une traçabilité totales." }
  ];
}

// ==========================================
// 8. CONDITIONAL FORMATTING LAYERS
// ==========================================
function buildSLAFormatting(s) { 
  let lastRow = s.getLastRow();
  let maxRow = Math.max(lastRow, 7);
  s.setConditionalFormatRules([
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("100.").setFontColor(STATUS_ONLINE).setBold(true).setRanges([s.getRange("H7:H" + maxRow)]).build(), 
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("99.").setFontColor("#FFF176").setBold(true).setRanges([s.getRange("H7:H" + maxRow)]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("OFFLINE").setFontColor(STATUS_OFFLINE).setBold(true).setRanges([s.getRange("A7:Z" + maxRow)]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("GLOBAL INFRASTRUCTURE").setBackground(BRAND_TERTIARY).setFontColor(TEXT_PRIMARY).setBold(true).setRanges([s.getRange("A7:Z" + maxRow)]).build()
  ]); 
  if (lastRow >= 7) s.setRowHeights(7, lastRow - 6, 45); 
}

function archiveSLAFormatting(s) { 
  let lastRow = s.getLastRow();
  let maxRow = Math.max(lastRow, 7);
  s.setConditionalFormatRules([
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("100.").setFontColor(STATUS_ONLINE).setBold(true).setRanges([s.getRange("I7:I" + maxRow)]).build(), 
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("99.").setFontColor("#FFF176").setBold(true).setRanges([s.getRange("I7:I" + maxRow)]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("OFFLINE").setFontColor(STATUS_OFFLINE).setBold(true).setRanges([s.getRange("A7:Z" + maxRow)]).build()
  ]); 
  if (lastRow >= 7) s.setRowHeights(7, lastRow - 6, 45); 
}

function buildActionFormatting(s) { 
  let lastRow = s.getLastRow();
  let maxRow = Math.max(lastRow, 7);
  s.setConditionalFormatRules([
    SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("Active & Enforced").setFontColor(STATUS_ONLINE).setBold(true).setRanges([s.getRange("E7:E" + maxRow)]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("Inactive").setFontColor(STATUS_OFFLINE).setBold(true).setRanges([s.getRange("E7:E" + maxRow)]).build()
  ]); 
}

function buildStatusFormatting(s) { 
  let lastRow = s.getLastRow();
  let maxRow = Math.max(lastRow, 7);
  s.setConditionalFormatRules([
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("ONLINE").setFontColor(STATUS_ONLINE).setBold(true).setRanges([s.getRange("A7:Z" + maxRow)]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("OFFLINE").setFontColor(STATUS_OFFLINE).setBold(true).setRanges([s.getRange("A7:Z" + maxRow)]).build()
  ]); 
  if (lastRow >= 7) s.setRowHeights(7, lastRow - 6, 45); 
}

function archiveStatusFormatting(s) { 
  let lastRow = s.getLastRow();
  let maxRow = Math.max(lastRow, 7);
  s.setConditionalFormatRules([
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("ONLINE").setFontColor(STATUS_ONLINE).setBold(true).setRanges([s.getRange("A7:Z" + maxRow)]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("OFFLINE").setFontColor(STATUS_OFFLINE).setBold(true).setRanges([s.getRange("A7:Z" + maxRow)]).build()
  ]); 
  if (lastRow >= 7) s.setRowHeights(7, lastRow - 6, 45); 
}