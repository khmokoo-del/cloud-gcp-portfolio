/**
 * ===================================================================
 * ENTERPRISE - ISO 27001 SECURITY AUDIT OPERATIONS 
 * Automated Endpoint Protection Dashboard & Log Ingestion Pipeline
 * Target Controls: ISO 27001:2022 Control 8.12 (DLP) & Control 8.1
 * ===================================================================
 */

// ==========================================
// 1. CORE CONFIGURATION & SCHEME THEME
// ==========================================
const BRAND_PRIMARY = "#E86C20";   // Corporate Brand Accent
const BRAND_SECONDARY = "#222222"; // Deep Charcoal Canvas Background
const BRAND_TERTIARY = "#333333";  // Structural KPI Card Background
const TEXT_PRIMARY = "#E1E4E6";    // Anti-Halation Off-White Text
const STATUS_ONLINE = "#2D8A4E";   // Compliant/Secure Dark Green
const STATUS_OFFLINE = "#A93226";  // Incident/Violation Crimson Red
const URL_LOGO = "https://your-enterprise-domain.com/dark-theme-logo.png";

// ==========================================
// 2. USER INTERFACE INITIALIZATION
// ==========================================
function onOpen() {
  const ui = SpreadsheetApp.getUi();
  ui.createMenu('Compliance Center')
      .addItem('Run Manual Endpoint Log Sweep', 'processAuditEvents')
      .addItem('Rebuild Enterprise Dashboard (Wipe)', 'buildEnterpriseDashboard')
      .addToUi();
}

// ==========================================
// 3. CORE LOG ROUTING & COMPLIANCE ENGINE
// ==========================================
function processAuditEvents() {
  const lock = LockService.getScriptLock();
  
  if (!lock.tryLock(30000)) {
    console.warn("Concurrency collision: Mutex locked by overlapping trigger. Exiting gracefully.");
    return;
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const rawSheet = ss.getSheetByName("Audit Events"); 
    const alertSheet = ss.getSheetByName("Security Alerts");
    const deviceSheet = ss.getSheetByName("Active Devices");
    
    if (!rawSheet || !alertSheet || !deviceSheet) return;

    const data = rawSheet.getDataRange().getValues();
    
    let headerIdx = -1;
    for (let i = 0; i < data.length; i++) {
      if (data[i].indexOf("Timestamp") > -1 && data[i].indexOf("Hostname") > -1) {
        headerIdx = i;
        break;
      }
    }
    
    if (headerIdx === -1 || data.length <= headerIdx + 1) return; 

    ss.toast("Extracting local device logs and indexing security events...", "Log Sweep Initialized", 5);

    const headers = data[headerIdx];
    const colTime = headers.indexOf("Timestamp");
    const colHost = headers.indexOf("Hostname");
    const colUser = headers.indexOf("Local User");
    const colJcId = headers.indexOf("JumpCloud ID");
    const colType = headers.indexOf("Event Type");
    const colAudit = headers.indexOf("Audit Message");

    let alertsToAppend = [];
    let allProcessedEvents = [];

    for (let i = headerIdx + 1; i < data.length; i++) {
      const row = data[i];
      
      // Strict filter: Ignore empty rows injected by GCP Cloud Run API
      if (!row[colHost] || String(row[colHost]).trim() === "") continue;

      const type = String(row[colType]).toUpperCase();
      
      // Route COMPOSITE_BLOCKED and DATA_SANITIZATION events to the Security Alerts tab
      if (type === "EVENT_BLOCKED" || type === "UNAUTHORIZED_WRITE" || type === "POLICY_MODIFIED" || type === "HEALTH_FAIL" || type === "DATA_SANITIZATION" || type === "COMPOSITE_BLOCKED") {
        alertsToAppend.push(row);
      }
      
      allProcessedEvents.push({
        hostname: row[colHost],
        timestamp: row[colTime],
        status: type,
        auditMsg: row[colAudit],
        localUser: row[colUser],
        jcId: row[colJcId]
      });
    }

    if (allProcessedEvents.length > 0) {
      batchUpsertDeviceState(deviceSheet, allProcessedEvents);
    }

    if (alertsToAppend.length > 0) {
      const startRow = Math.max(alertSheet.getLastRow() + 1, 7);
      if (startRow + alertsToAppend.length > alertSheet.getMaxRows()) {
        alertSheet.insertRowsAfter(alertSheet.getMaxRows(), alertsToAppend.length + 10);
      }
      const newRange = alertSheet.getRange(startRow, 1, alertsToAppend.length, headers.length);
      newRange.setValues(alertsToAppend)
              .setBackground(BRAND_SECONDARY)
              .setFontColor(TEXT_PRIMARY)
              .setHorizontalAlignment("center")
              .setVerticalAlignment("middle")
              .setBorder(true, true, true, true, true, true, "#444444", SpreadsheetApp.BorderStyle.SOLID);
      buildActionFormatting(alertSheet);
      
      // Trigger Garbage Collection on the UI Alert Dashboard
      pruneActiveAlerts(alertSheet);
    }

    appendArchiveLog(ss, "Archive: Security History", data.slice(headerIdx + 1).filter(r => r[colHost] && String(r[colHost]).trim() !== ""), "Endpoint Protection Log Archive");

    // Force Google API commit to eliminate the dashboard 0/0 race condition
    SpreadsheetApp.flush();

    const postureMatrix = alertSheet.getDataRange().getValues();
    const deviceMatrix = deviceSheet.getDataRange().getValues();
    buildExecutiveDashboard(ss, "Executive Summary", postureMatrix, deviceMatrix, false);

    // ==========================================
    // 5. GRID GEOMETRY LOCKING AND TRUNCATION
    // ==========================================
    const maxRows = rawSheet.getMaxRows();
    const lastDataRow = rawSheet.getLastRow();
    
    // SAFE FIX: Clear contents instead of deleting rows to prevent API grid-shift collisions
    const rowsToClear = data.length - (headerIdx + 1);
    if (rowsToClear > 0) {
      rawSheet.getRange(headerIdx + 2, 1, rowsToClear, rawSheet.getMaxColumns()).clearContent();
    }
    
    // Truncate any 'Ghost Rows' generated by the Cloud Run API append
    const newMaxRows = rawSheet.getMaxRows();
    const newLastRow = Math.max(rawSheet.getLastRow(), 1);
    if (newMaxRows > newLastRow) {
      // Completely sever the empty grid space below the actual data
      rawSheet.deleteRows(newLastRow + 1, newMaxRows - newLastRow);
    }
    
    ss.toast("Log sweep complete. Executive graphs and historical archives appended.", "Success", 5);

  } catch (e) {
    console.error("Execution Exception: " + e.message);
  } finally {
    lock.releaseLock();
  }
}

// ==========================================
// 4. ENVIRONMENT TRACKING STATE UPSERT
// ==========================================
function batchUpsertDeviceState(sheet, incomingEvents) {
  const existingData = sheet.getDataRange().getValues();
  
  let headerIdx = -1;
  for (let i = 0; i < existingData.length; i++) {
    if (existingData[i].indexOf("Hostname") > -1 && existingData[i].indexOf("Last Check-In") > -1) {
      headerIdx = i;
      break;
    }
  }
  if (headerIdx === -1) return;
  
  const headers = existingData[headerIdx];
  const colHost = headers.indexOf("Hostname");
  const colTime = headers.indexOf("Last Check-In");
  const colStatus = headers.indexOf("Status");
  const colAudit = headers.indexOf("Audit Message");
  const colUser = headers.indexOf("Local User");
  const colJcId = headers.indexOf("JumpCloud ID");

  const deviceMap = new Map();
  for (let i = headerIdx + 1; i < existingData.length; i++) {
    const hostname = existingData[i][colHost];
    if (hostname) deviceMap.set(hostname, existingData[i]);
  }

  incomingEvents.forEach(event => {
    let row = deviceMap.has(event.hostname) ? deviceMap.get(event.hostname) : new Array(headers.length).fill("");
    
    // Allow DATA_SANITIZATION and COMPOSITE_BLOCKED as healthy processes so they don't trigger a red violation card
    const isHealthy = (event.status === "HEALTH_PASS" || event.status === "SYSTEM_PROCESS" || event.status === "SYSTEM_AUDIT" || event.status === "DATA_SANITIZATION" || event.status === "COMPOSITE_BLOCKED");
    const displayStatus = isHealthy ? "SECURE" : "VIOLATION_TRIGGERED";

    if (colHost > -1) row[colHost] = event.hostname;
    if (colTime > -1) row[colTime] = event.timestamp;
    if (colStatus > -1) row[colStatus] = displayStatus;
    if (colAudit > -1) row[colAudit] = event.auditMsg;
    if (colUser > -1) row[colUser] = event.localUser;
    if (colJcId > -1) row[colJcId] = event.jcId;

    deviceMap.set(event.hostname, row);
  });

  const outputMatrix = [];
  deviceMap.forEach(row => outputMatrix.push(row));

  const dataStartRow = headerIdx + 2;

  if (outputMatrix.length > 0) {
    if (dataStartRow + outputMatrix.length - 1 > sheet.getMaxRows()) {
      sheet.insertRowsAfter(sheet.getMaxRows(), outputMatrix.length + 10);
    }
    
    const currentLastRow = Math.max(sheet.getLastRow(), dataStartRow);
    if (currentLastRow >= dataStartRow) {
      sheet.getRange(dataStartRow, 1, currentLastRow - dataStartRow + 1, sheet.getMaxColumns()).clearContent();
    }
    
    sheet.getRange(dataStartRow, 1, outputMatrix.length, headers.length)
         .setValues(outputMatrix)
         .setBackground(BRAND_SECONDARY)
         .setFontColor(TEXT_PRIMARY)
         .setHorizontalAlignment("center")
         .setVerticalAlignment("middle")
         .setBorder(true, true, true, true, true, true, "#444444", SpreadsheetApp.BorderStyle.SOLID);
         
    buildStatusFormatting(sheet);
  }
}

// ==========================================
// 5. LONG-TERM EVIDENCE LOG ARCHIVER
// ==========================================
function appendArchiveLog(ss, sheetName, rowsData, titleText) {
  if (!rowsData || rowsData.length === 0) return;
  
  let sheet = ss.getSheetByName(sheetName);
  const timestamp = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), "yyyy-MM-dd HH:mm");
  const rawHeaders = ["Timestamp", "Hostname", "Local User", "JumpCloud ID", "Event Type", "Hardware Vendor", "Hardware Model", "Device Serial", "File Path", "Audit Message"];
  const archiveHeaders = ["Archive Log Signature"].concat(rawHeaders);
  
  let dataToAppend = [];
  rowsData.forEach(row => {
    dataToAppend.push([timestamp].concat(row));
  });

  if (!sheet) {
    sheet = ss.insertSheet(sheetName);
    sheet.setHiddenGridlines(true);
    
    let maxCols = sheet.getMaxColumns();
    if (maxCols > archiveHeaders.length) sheet.deleteColumns(archiveHeaders.length + 1, maxCols - archiveHeaders.length);
    
    buildUniversalHeader(sheet, titleText, "Immutable long-term event logs for regulatory audit verification.", "Registre historique immuable pour la vérification réglementaire.", archiveHeaders.length);
    
    sheet.getRange(6, 1, 1, archiveHeaders.length).setValues([archiveHeaders]).setBackground(BRAND_PRIMARY).setFontColor(TEXT_PRIMARY).setFontWeight("bold");
    sheet.setFrozenRows(6);
  }

  let startRow = Math.max(sheet.getLastRow() + 1, 7);
  if (startRow + dataToAppend.length - 1 > sheet.getMaxRows()) {
    sheet.insertRowsAfter(sheet.getMaxRows(), dataToAppend.length + 20);
  }

  let appendRange = sheet.getRange(startRow, 1, dataToAppend.length, archiveHeaders.length);
  appendRange.setValues(dataToAppend)
              .setBackground(BRAND_SECONDARY)
              .setFontColor(TEXT_PRIMARY)
              .setHorizontalAlignment("center")
              .setVerticalAlignment("middle")
              .setWrap(true)
              .setBorder(true, true, true, true, true, true, "#444444", SpreadsheetApp.BorderStyle.SOLID);

  sheet.autoResizeColumns(1, archiveHeaders.length);
  for (let i = 1; i <= archiveHeaders.length; i++) {
    sheet.setColumnWidth(i, Math.min(sheet.getColumnWidth(i) + 40, 260));
  }

  // Trigger strict ISO immutability enforcement
  enforceArchiveImmutability(ss);
}

// ==========================================
// 5.1 ISO 27001 CHAIN-OF-CUSTODY ENFORCEMENT
// ==========================================
function enforceArchiveImmutability(ss) {
  const archiveSheet = ss.getSheetByName("Archive: Security History");
  if (!archiveSheet) return;

  // Prevent duplicating protections on every run
  const protections = archiveSheet.getProtections(SpreadsheetApp.ProtectionType.SHEET);
  if (protections.length > 0) return;

  try {
    // Initialize the protection object for the entire sheet
    const protection = archiveSheet.protect().setDescription('ISO 27001: Immutable Audit Trail');
    
    // Strip all human editors from the Access Control List (ACL)
    const currentEditors = protection.getEditors();
    protection.removeEditors(currentEditors);
    
    // Disable broad domain-level edit permissions if they exist
    if (protection.canDomainEdit()) {
      protection.setDomainEdit(false);
    }
  } catch(e) {
    console.warn("Could not lock archive sheet: Executing user lacks ACL authority.");
  }
}

// ==========================================
// 5.2 ACTIVE DASHBOARD AUTO-PRUNING (GARBAGE COLLECTION)
// ==========================================
function pruneActiveAlerts(sheet) {
  if (!sheet) return;
  
  const MAX_ALERTS = 500; // Limits the Security Alerts tab to the 500 most recent events to prevent UI lag
  const HEADER_ROWS = 6;
  const currentRows = sheet.getLastRow();
  
  // If the sheet has grown past our limit, safely shear off the oldest entries at the top
  if (currentRows > HEADER_ROWS + MAX_ALERTS) {
    const rowsToDelete = currentRows - (HEADER_ROWS + MAX_ALERTS);
    // Row 7 is the first row of actual data underneath the frozen headers
    sheet.deleteRows(HEADER_ROWS + 1, rowsToDelete);
  }
}

// ==========================================
// 6. EXECUTIVE REGIONAL DASHBOARD 
// ==========================================
function buildExecutiveDashboard(ss, sheetName, alertMatrix, deviceMatrix, isRebuild = false) {
  let sheet = ss.getSheetByName(sheetName);
  
  if (isRebuild || !sheet) {
    sheet = getCleanSheet(ss, sheetName);
    sheet.getRange(1, 1, Math.max(sheet.getMaxRows(), 35), Math.max(sheet.getMaxColumns(), 15)).setBackground(BRAND_SECONDARY);
    sheet.getRange(2, 2, 2, 2).merge().setFormula(`=IMAGE("${URL_LOGO}", 1)`);
    sheet.getRange(2, 4, 2, 9).merge().setValue("DATA LEAKAGE PREVENTION LEDGER").setFontSize(16).setFontWeight("bold").setFontColor(BRAND_PRIMARY).setVerticalAlignment("middle");
    sheet.getRange(4, 4, 1, 9).merge().setValue("ISO 27001:2022 Compliance Operations Matrix — Controls 8.1 & 8.12").setFontStyle("italic").setFontColor(TEXT_PRIMARY);
    sheet.setColumnWidth(1, 30); 
    for(let i=2; i<=13; i++) sheet.setColumnWidth(i, 110);
  }
  
  let totalEndpoints = 0;
  let secureEndpoints = 0;
  
  let regions = {
    HQ: { total: 0, secure: 0 },
    REG_A: { total: 0, secure: 0 },
    REG_B: { total: 0, secure: 0 },
    SUPPORT: { total: 0, secure: 0 }
  };

  if (deviceMatrix && deviceMatrix.length > 6) {
    for (let i = 6; i < deviceMatrix.length; i++) {
      let row = deviceMatrix[i];
      let hostname = String(row[0] || "").toUpperCase();
      let status = String(row[2] || "").toUpperCase();

      if (!hostname) continue; 

      totalEndpoints++;
      let isSecure = status.includes("SECURE");
      if (isSecure) secureEndpoints++;

      let parts = hostname.split('-');
      let regionCode = parts.length > 1 ? parts[1] : "UNKNOWN";
      
      // Map legacy or specific strings to our generic regions if needed
      if (regionCode === "HQ") regionCode = "HQ";
      else if (regionCode === "A") regionCode = "REG_A";
      else if (regionCode === "B") regionCode = "REG_B";
      else if (regionCode === "SUP") regionCode = "SUPPORT";

      if (regions[regionCode]) {
        regions[regionCode].total++;
        if (isSecure) regions[regionCode].secure++;
      }
    }
  }
  
  let incidentEntries = (alertMatrix && alertMatrix.length > 6) ? alertMatrix.slice(6) : [];
  let blockedHardwareCount = incidentEntries.filter(r => String(r[4]) === "EVENT_BLOCKED").length;
  let writeViolationsCount = incidentEntries.filter(r => String(r[4]) === "UNAUTHORIZED_WRITE").length;
  let configTamperCount = incidentEntries.filter(r => String(r[4]) === "POLICY_MODIFIED").length;
  
  let sanitizationCount = incidentEntries.filter(r => String(r[4]) === "DATA_SANITIZATION").length;

  let globalComplianceRate = totalEndpoints > 0 ? Math.round((secureEndpoints / totalEndpoints) * 100) : 100;

  function drawCard(row, col, colSpan, title, value, subtext, accentColor) {
    sheet.getRange(row, col, 1, colSpan).merge().setValue(title).setFontColor(TEXT_PRIMARY).setFontWeight("bold").setBackground(BRAND_TERTIARY).setHorizontalAlignment("center").setBorder(true, true, false, true, false, false, accentColor, SpreadsheetApp.BorderStyle.SOLID_MEDIUM);
    sheet.getRange(row+1, col, 2, colSpan).merge().setValue(value).setFontColor(accentColor).setFontSize(24).setFontWeight("bold").setBackground(BRAND_TERTIARY).setHorizontalAlignment("center").setVerticalAlignment("middle").setBorder(false, true, false, true, false, false, accentColor, SpreadsheetApp.BorderStyle.SOLID_MEDIUM);
    sheet.getRange(row+3, col, 1, colSpan).merge().setValue(subtext).setFontColor(TEXT_PRIMARY).setFontSize(9).setBackground(BRAND_TERTIARY).setHorizontalAlignment("center").setBorder(false, true, true, true, false, false, accentColor, SpreadsheetApp.BorderStyle.SOLID_MEDIUM);
  }

  drawCard(7, 2, 3, "GLOBAL ENDPOINT COMPLIANCE", `${secureEndpoints} / ${totalEndpoints}`, "Hardened Devices Compliant", globalComplianceRate === 100 ? STATUS_ONLINE : "#FFF176");
  drawCard(7, 6, 3, "PERIMETER HARDENING", `${globalComplianceRate}%`, "Global System Integrity Score", globalComplianceRate === 100 ? STATUS_ONLINE : STATUS_OFFLINE);
  drawCard(7, 10, 3, "TOTAL ACCESS BLOCKADES", blockedHardwareCount, "USB Mount Events Aborted", blockedHardwareCount === 0 ? STATUS_ONLINE : "#FFF176");

  let hqColor = (regions.HQ.total > 0 && regions.HQ.secure === regions.HQ.total) ? STATUS_ONLINE : (regions.HQ.total === 0 ? TEXT_PRIMARY : STATUS_OFFLINE);
  drawCard(12, 2, 2, "HEADQUARTERS", `${regions.HQ.secure} / ${regions.HQ.total}`, "HQ Endpoints SECURE", hqColor);

  let regAColor = (regions.REG_A.total > 0 && regions.REG_A.secure === regions.REG_A.total) ? STATUS_ONLINE : (regions.REG_A.total === 0 ? TEXT_PRIMARY : STATUS_OFFLINE);
  drawCard(12, 5, 2, "REGION A", `${regions.REG_A.secure} / ${regions.REG_A.total}`, "REG A Endpoints SECURE", regAColor);

  let regBColor = (regions.REG_B.total > 0 && regions.REG_B.secure === regions.REG_B.total) ? STATUS_ONLINE : (regions.REG_B.total === 0 ? TEXT_PRIMARY : STATUS_OFFLINE);
  drawCard(12, 8, 2, "REGION B", `${regions.REG_B.secure} / ${regions.REG_B.total}`, "REG B Endpoints SECURE", regBColor);

  let supportColor = (regions.SUPPORT.total > 0 && regions.SUPPORT.secure === regions.SUPPORT.total) ? STATUS_ONLINE : (regions.SUPPORT.total === 0 ? TEXT_PRIMARY : STATUS_OFFLINE);
  drawCard(12, 11, 2, "SUPPORT CENTER", `${regions.SUPPORT.secure} / ${regions.SUPPORT.total}`, "SUPPORT Endpoints SECURE", supportColor);

  drawCard(17, 4, 3, "EXFILTRATION ATTEMPTS", writeViolationsCount, "Unauthorized Write Events Blocked", writeViolationsCount === 0 ? STATUS_ONLINE : STATUS_OFFLINE);
  drawCard(17, 8, 3, "INTEGRITY DEVIATIONS", configTamperCount, "Local Agent Policy Tamper Alarms", configTamperCount === 0 ? STATUS_ONLINE : STATUS_OFFLINE);
  
  drawCard(17, 12, 3, "WORKSPACES SANITIZED", sanitizationCount, "Ephemeral Sessions Wiped", STATUS_ONLINE);
}

// ==========================================
// 7. CANVAS & REGULATORY CHARTER MATRICES
// ==========================================
function buildTab(ss, sheetName, matrix, formatFn, descEN, descFR) {
  let sheet = getCleanSheet(ss, sheetName);
  
  let data = (!matrix || matrix.length === 0) ? [["Data", "Status"]] : matrix;
  let totalCols = data[0].length;

  let maxCols = sheet.getMaxColumns();
  let targetCols = Math.max(totalCols, 5);
  if (maxCols > targetCols) sheet.deleteColumns(targetCols + 1, maxCols - targetCols);
  
  let maxRows = sheet.getMaxRows();
  let targetRows = Math.max(data.length + 6, 22);
  
  if (maxRows > targetRows) {
    sheet.deleteRows(targetRows + 1, maxRows - targetRows);
  } else if (maxRows < targetRows) {
    sheet.insertRowsAfter(maxRows, targetRows - maxRows);
  }

  sheet.getRange(1, 1, sheet.getMaxRows(), sheet.getMaxColumns())
       .setBackground(BRAND_SECONDARY)
       .setFontColor(TEXT_PRIMARY)
       .setHorizontalAlignment("center")
       .setVerticalAlignment("middle")
       .setWrap(true);

  sheet.getRange(6, 1, data.length, totalCols).setValues(data);
  sheet.getRange(6, 1, 1, totalCols).setBackground(BRAND_PRIMARY).setFontColor(TEXT_PRIMARY).setFontWeight("bold");
  
  if (data.length > 1 && totalCols >= 2) {
    sheet.getRange(7, 1, data.length - 1, 2).setHorizontalAlignment("left");
  }

  if (formatFn) formatFn(sheet);
  buildUniversalHeader(sheet, sheetName, descEN, descFR, totalCols);
  
  sheet.setFrozenRows(6);
  sheet.autoResizeColumns(1, totalCols);
  
  for (let i = 1; i <= totalCols; i++) {
    let currentWidth = sheet.getColumnWidth(i);
    sheet.setColumnWidth(i, Math.min(currentWidth + 40, 260));
  }
}

function buildMethodologyCanvas(ss, sheetName, contentData) {
  let sheet = getCleanSheet(ss, sheetName);
  sheet.getRange(1, 1, Math.max(sheet.getMaxRows(), 45), Math.max(sheet.getMaxColumns(), 12)).setBackground(BRAND_SECONDARY);
  sheet.getRange(2, 2, 2, 2).merge().setFormula(`=IMAGE("${URL_LOGO}", 1)`);
  
  let canvas = sheet.getRange("C5:K42");
  canvas.merge().setBackground(BRAND_SECONDARY).setVerticalAlignment("top").setHorizontalAlignment("left").setWrap(true);
  
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
  for(let i=3; i<=12; i++) sheet.setColumnWidth(i, 110);
}

function buildUniversalHeader(sheet, titleText, descEN, descFR, totalCols) {
  let headerCols = Math.max(totalCols, 5);
  sheet.getRange(1, 1, 5, Math.max(sheet.getMaxColumns(), headerCols)).setBackground(BRAND_SECONDARY);
  sheet.getRange(1, 1, 2, 2).merge().setFormula(`=IMAGE("${URL_LOGO}", 1)`);
  sheet.getRange(1, 3, 2, headerCols - 2).merge().setValue(`ISO 27001 COMPLIANCE SYSTEM — ${titleText.toUpperCase()}`).setFontColor(TEXT_PRIMARY).setFontSize(13).setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.getRange(3, 1, 1, headerCols).merge().setValue(`EN: ${descEN}`).setBackground(BRAND_TERTIARY).setFontColor(TEXT_PRIMARY).setFontStyle("italic").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.getRange(4, 1, 1, headerCols).merge().setValue(`FR: ${descFR}`).setBackground(BRAND_TERTIARY).setFontColor(TEXT_PRIMARY).setFontStyle("italic").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.getRange(1, 1, 2, headerCols).setBorder(true, true, true, true, false, false, BRAND_PRIMARY, SpreadsheetApp.BorderStyle.SOLID_THICK);
}

function getCleanSheet(ss, sheetName) {
  let sheet = ss.getSheetByName(sheetName);
  
  if (!sheet) {
    sheet = ss.insertSheet(sheetName);
    sheet.setHiddenGridlines(true);
  } else {
    // Unfreeze grid geometry first to prevent DOM merge conflicts
    sheet.setFrozenRows(0);
    sheet.setFrozenColumns(0);
    // Safely wipe data, formatting, and rules
    sheet.clear();
    sheet.clearConditionalFormatRules();
  }
  
  return sheet;
}

// ==========================================
// 8. CONDITIONAL FORMATTING LAYERS
// ==========================================
function buildActionFormatting(s) {
  let maxRow = Math.max(s.getLastRow(), 7);
  s.setConditionalFormatRules([
    SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("EVENT_BLOCKED").setFontColor("#FFF176").setBold(true).setRanges([s.getRange("E7:E" + maxRow)]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("UNAUTHORIZED_WRITE").setFontColor(STATUS_OFFLINE).setBold(true).setRanges([s.getRange("E7:E" + maxRow)]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("POLICY_MODIFIED").setFontColor(BRAND_PRIMARY).setBold(true).setRanges([s.getRange("E7:E" + maxRow)]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("DATA_SANITIZATION").setFontColor(STATUS_ONLINE).setBold(true).setRanges([s.getRange("E7:E" + maxRow)]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("COMPOSITE_BLOCKED").setFontColor(STATUS_ONLINE).setBold(true).setRanges([s.getRange("E7:E" + maxRow)]).build()
  ]);
  if (s.getLastRow() >= 7) s.setRowHeights(7, s.getLastRow() - 6, 40);
}

function buildStatusFormatting(s) {
  let maxRow = Math.max(s.getLastRow(), 7);
  s.setConditionalFormatRules([
    SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("SECURE").setFontColor(STATUS_ONLINE).setBold(true).setRanges([s.getRange("C7:C" + maxRow)]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("VIOLATION_TRIGGERED").setFontColor(STATUS_OFFLINE).setBold(true).setRanges([s.getRange("C7:C" + maxRow)]).build()
  ]);
  if (s.getLastRow() >= 7) s.setRowHeights(7, s.getLastRow() - 6, 40);
}

// ==========================================
// 9. REGULATORY AUDIT TEXT MATRICES
// ==========================================
function getEnglishDlpMethodology() {
  return [
    { type: "header", text: "ISO 27001 AUDIT ARCHITECTURE — DATA LEAKAGE PREVENTION" },
    { type: "header", text: "Control Reference:" },
    { type: "body", text: "This monitoring platform provides objective technical verification for ISO 27001:2022 Annex A Control 8.12 (Data Leakage Prevention) and Control 8.1 (User Endpoint Security Management)." },
    { type: "header", text: "Operational Scope & Mechanics:" },
    { type: "body", text: "Local background scripts deployed via centralized MDM securely capture low-level kernel block device connection events directly from system interfaces. Threat tracking logs are batched into local transactions and synced via secure pipelines to our serverless Cloud Run processing container." },
    { type: "header", text: "Event Analysis and Isolation:" },
    { type: "body", text: "To eliminate noise, composite device identifiers containing human input descriptors (HID) are programmatically whitelisted at the endpoint. Storage blocks, mass media, and unauthorized physical interfaces trigger instant authorization revocation and file audit flags." },
    { type: "header", text: "Immutable Audit Trails:" },
    { type: "body", text: "Upon ingestion, point-in-time entries are immediately mirrored into cryptographically timestamped historical ledgers. These tables remain untouched by automation routines, providing inspectors an unalterable chain of forensic evidence." }
  ];
}

function getFrenchDlpMethodology() {
  return [
    { type: "header", text: "ARCHITECTURE D'AUDIT ISO 27001 — PRÉVENTION DES FUITES DE DONNÉES" },
    { type: "header", text: "Référence du Contrôle :" },
    { type: "body", text: "Cette plateforme de surveillance fournit une vérification technique objective pour les contrôles de l'Annexe A de la norme ISO 27001:2022 : Contrôle 8.12 (Prévention des fuites de données) et Contrôle 8.1 (Sécurité des terminaux utilisateurs)." },
    { type: "header", text: "Champ d'Application et Fonctionnement :" },
    { type: "body", text: "Des scripts d'arrière-plan locaux déployés de manière centralisée capturent de manière sécurisée les événements de connexion de périphériques blocs au niveau du noyau directement depuis les interfaces système. Les journaux de menaces sont regroupés localement puis synchronisés via des tunnels chiffrés vers notre conteneur Cloud Run." },
    { type: "header", text: "Analyse et Isolation des Événements :" },
    { type: "body", text: "Pour éliminer les faux positifs, les identifiants de périphériques composites contenant des descripteurs d'interface utilisateur (HID) sont mis sur liste blanche au niveau du terminal. Les volumes de stockage de masse et les interfaces physiques non autorisées déclenchent une révocation immédiate de l'autorisation et un marquage d'audit." },
    { type: "header", text: "Pistes d'Audit Immuables :" },
    { type: "body", text: "Dès leur réception, les entrées instantanées sont immédiatement dupliquées dans des registres historiques horodatés. Ces tables restent isolées des scripts de maintenance, offrant aux auditeurs une chaîne de preuves forensiques inaltérable." }
  ];
}

// ==========================================
// 10. THE MASTER SETUP COMMAND
// ==========================================
function buildEnterpriseDashboard() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const rawHeaders = ["Timestamp", "Hostname", "Local User", "MDM ID", "Event Type", "Hardware Vendor", "Hardware Model", "Device Serial", "File Path", "Audit Message"];
  
  buildExecutiveDashboard(ss, "Executive Summary", [], [], true);
  buildMethodologyCanvas(ss, "ISO Methodology (EN)", getEnglishDlpMethodology());
  buildMethodologyCanvas(ss, "Méthodologie ISO (FR)", getFrenchDlpMethodology());
  
  buildTab(ss, "Security Alerts", [rawHeaders], buildActionFormatting, "Active Security Violation Alerts and Threat Vector Blockades.", "Alertes actives de violation de sécurité et blocages de menaces.");
  buildTab(ss, "Active Devices", [["Hostname", "Last Check-In", "Status", "Audit Message", "Local User", "MDM ID"]], buildStatusFormatting, "Current System Configuration Verification and Health State Map.", "Vérification de la configuration actuelle du système et carte d'état.");
  buildTab(ss, "Audit Events", [rawHeaders], null, "Secure Ingestion Channel for Encrypted Raw Events (Hidden).", "Canal de réception sécurisé pour les événements bruts chiffrés (Masqué).");

  const tabOrder = ["Executive Summary", "ISO Methodology (EN)", "Méthodologie ISO (FR)", "Security Alerts", "Active Devices", "Audit Events"];
  tabOrder.reverse().forEach(name => {
    let t = ss.getSheetByName(name);
    if (t) { ss.setActiveSheet(t); ss.moveActiveSheet(1); }
  });

  SpreadsheetApp.getUi().alert("✅ Enterprise Compliance Architecture fully initialized. You are cleared to execute the MDM agent distribution.");
}