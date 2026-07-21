/**
 * Project: Workspace_Sanitization_ETL_Pipeline
 * Description: Multi-tiered Business Intelligence Application for Google Workspace Compliance.
 * Automates data extraction from BigQuery, formats executive scorecards, 
 * builds manager sign-off directories, generates forensic audit ledgers, and highlights security risks.
 * Author: Khutso Mokoo 
 */

// ==========================================
// ENTERPRISE CONFIGURATION & PALETTE
// ==========================================
const PROJECT_ID = 'your-gcp-project-id';
// Points to the deduplicated BigQuery view
const BQ_TABLE = '`your-gcp-project-id.compliance_dataset.clean_audit_log`'; 
const INTERNAL_DOMAIN = 'your-domain.com';
const TIMEZONE = 'UTC'; // Adjust to your corporate timezone

const COLOR = {
  brandAccent: "#ED7034",
  darkGrey: "#2C3E50",
  lightBg: "#F8F9FA",
  borderGrey: "#E0E0E0",
  alertRed: "#E74C3C",
  white: "#FFFFFF"
};

// ==========================================
// UI INITIALIZATION
// ==========================================
function onOpen() {
  var ui = SpreadsheetApp.getUi();
  ui.createMenu('☁️ Data Operations')
      .addItem('Generate Executive Audit Report', 'executeETLPipeline')
      .addToUi();
}

// ==========================================
// MASTER ORCHESTRATOR (ETL)
// ==========================================
function executeETLPipeline() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  ss.toast("Initiating BigQuery secure data extraction...", "Pipeline Active", 5);

  try {
    // 1. Build Tab 1: Executive Summary
    buildExecutiveSummary(ss);
    
    // 2. Build Tab 2: Target Directory
    buildTargetDirectory(ss);
    
    // 3. Build Tab 3: Official Audit Ledger
    buildAuditLedger(ss);

    // 4. Build Tab 4: Security Risk Exposures (All Shared)
    buildSecurityExposures(ss);
    
    // 5. Build Tab 5: CRITICAL External Threats (DLP)
    buildExternalThreats(ss);

    // 6. Build Tab 6: Shadow IT & Malware Risks (Executables)
    buildShadowITRisk(ss);
    
    ss.toast("All dashboards successfully synchronized with Google Cloud.", "Execution Complete", 5);
    
  } catch (err) {
    SpreadsheetApp.getUi().alert('System Error: Pipeline failed. Details: ' + err.toString());
  }
}

// ==========================================
// HELPER: BIGQUERY SQL EXECUTION
// ==========================================
function fetchFromBigQuery(sql) {
  var request = { query: sql, useLegacySql: false };
  var queryResults = BigQuery.Jobs.query(request, PROJECT_ID);
  var jobId = queryResults.jobReference.jobId;
  
  var sleepTimeMs = 500;
  while (!queryResults.jobComplete) {
    Utilities.sleep(sleepTimeMs);
    sleepTimeMs *= 2;
    queryResults = BigQuery.Jobs.getQueryResults(PROJECT_ID, jobId);
  }
  
  var rows = queryResults.rows || [];
  var pageToken = queryResults.pageToken;
  
  // Handle Pagination to prevent silent data loss
  while (pageToken) {
    var pageResults = BigQuery.Jobs.getQueryResults(PROJECT_ID, jobId, {pageToken: pageToken});
    if (pageResults.rows) {
      rows = rows.concat(pageResults.rows);
    }
    pageToken = pageResults.pageToken;
  }
  
  if (rows.length === 0) return [];
  
  var data = [];
  for (var i = 0; i < rows.length; i++) {
    var cols = rows[i].f;
    var rowData = [];
    for (var j = 0; j < cols.length; j++) {
      var val = cols[j].v;
      
      // Convert BigQuery stringified numbers back to actual numbers
      if (val !== null && !isNaN(val) && val !== "") {
        val = Number(val);
      }
      
      rowData.push(val);
    }
    data.push(rowData);
  }
  return data;
}

// ==========================================
// TAB 1: EXECUTIVE SUMMARY BUILDER
// ==========================================
function buildExecutiveSummary(ss) {
  var sheetName = "Executive Summary / Résumé Exécutif";
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) { sheet = ss.insertSheet(sheetName, 0); }
  sheet.clear();
  
  // SQL Query: Calculate top-level aggregates
  var sqlMetrics = `
    SELECT 
      COUNT(DISTINCT target_user), 
      COUNT(file_id), 
      ROUND(SUM(file_size_bytes)/1048576, 2), 
      COUNTIF(is_shared = TRUE) 
    FROM ${BQ_TABLE} WHERE organizational_unit IS NOT NULL
  `;
  var metricsData = fetchFromBigQuery(sqlMetrics);
  if (metricsData.length === 0) return;
  
  // SQL Query: Regional Breakdown
  var sqlRegion = `
    SELECT 
      SPLIT(organizational_unit, '/')[SAFE_OFFSET(2)] as region, 
      COUNT(DISTINCT CASE WHEN LOWER(SPLIT(organizational_unit, '/')[SAFE_OFFSET(3)]) LIKE '%agent%' THEN target_user END) as agents,
      COUNT(DISTINCT CASE WHEN LOWER(SPLIT(organizational_unit, '/')[SAFE_OFFSET(3)]) LIKE '%supervisor%' THEN target_user END) as supervisors,
      COUNT(file_id) as file_count,
      ROUND(SUM(file_size_bytes)/1048576, 2) as mb_count
    FROM ${BQ_TABLE} WHERE organizational_unit IS NOT NULL 
    GROUP BY region ORDER BY region
  `;
  var regionData = fetchFromBigQuery(sqlRegion);

  // Formatting: Main Title
  sheet.getRange("A1:E1").merge().setValue("ENTERPRISE WORKSPACE COMPLIANCE: EXECUTIVE SUMMARY")
       .setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold")
       .setHorizontalAlignment("center").setVerticalAlignment("middle").setFontSize(14);
  sheet.setRowHeight(1, 40);

  // Formatting: Executive Context Description
  var execDescription = "This dashboard provides a high-level overview of the Workspace compliance audit, tracking reclaimed storage and identifying security exposures across all regional organizational units.\n\n" +
                        "Ce tableau de bord fournit un aperçu de haut niveau de l'audit de conformité Workspace, suivant le stockage récupéré et identifiant les expositions de sécurité à travers toutes les unités organisationnelles régionales.";
  sheet.getRange("A2:E2").merge().setValue(execDescription)
       .setBackground(COLOR.lightBg).setFontColor(COLOR.darkGrey).setFontStyle("italic")
       .setHorizontalAlignment("center").setVerticalAlignment("middle").setWrap(true);
  sheet.setRowHeight(2, 70);
  
  // Formatting: Top Level Scorecard
  var scoreHeaders = [
    "Total Accounts Audited\nTotal des Comptes Audités", 
    "Total Files Flagged\nTotal des Fichiers Signalés", 
    "Storage Reclaimed (MB)\nStockage Récupéré (Mo)", 
    "Security Risk Exposures\nRisques de Sécurité Exposés"
  ];
  sheet.getRange(4, 1, 1, 4).setValues([scoreHeaders]).setBackground(COLOR.brandAccent)
       .setFontColor(COLOR.white).setFontWeight("bold").setWrap(true).setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(4, 50);
  
  sheet.getRange(5, 1, 1, 4).setValues(metricsData).setFontSize(18).setFontWeight("bold")
       .setHorizontalAlignment("center").setVerticalAlignment("middle").setBackground(COLOR.lightBg);
  sheet.setRowHeight(5, 60);
  
  // Formatting: Region Matrix
  sheet.getRange("A8:E8").merge().setValue("REGIONAL BREAKDOWN / RÉPARTITION RÉGIONALE")
       .setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold")
       .setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(8, 30);
  
  var regionHeaders = [
    "Region\nRégion", 
    "Total Agents\nTotal des Agents", 
    "Total Supervisors\nTotal des Superviseurs", 
    "File Count\nNombre de Fichiers", 
    "Storage Reclaimed (MB)\nStockage Récupéré (Mo)"
  ];
  sheet.getRange(9, 1, 1, 5).setValues([regionHeaders]).setBackground(COLOR.darkGrey)
       .setFontColor(COLOR.white).setFontWeight("bold").setWrap(true).setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(9, 45);
       
  if (regionData.length > 0) {
    var regionRange = sheet.getRange(10, 1, regionData.length, 5);
    regionRange.setValues(regionData).setHorizontalAlignment("center").setVerticalAlignment("middle");
    regionRange.setBorder(true, true, true, true, true, true, COLOR.borderGrey, SpreadsheetApp.BorderStyle.SOLID);
  }
  
  for(var c=1; c<=5; c++) { sheet.autoResizeColumn(c); sheet.setColumnWidth(c, sheet.getColumnWidth(c) + 30); }
}

// ==========================================
// TAB 2: TARGET DIRECTORY BUILDER
// ==========================================
function buildTargetDirectory(ss) {
  var sheetName = "Target Directory / Annuaire des Cibles";
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) { sheet = ss.insertSheet(sheetName, 1); }
  
  if (sheet.getFilter() !== null) {
    sheet.getFilter().remove();
  }
  
  // Preserve manager sign-offs before clearing the sheet
  var existingStatuses = {};
  if (sheet.getLastRow() > 2) {
    var oldData = sheet.getRange(3, 3, sheet.getLastRow() - 2, 2).getValues(); 
    for (var k = 0; k < oldData.length; k++) {
      existingStatuses[oldData[k][0]] = oldData[k][1];
    }
  }

  sheet.clear();
  sheet.clearFormats();
  sheet.clearConditionalFormatRules();
  
  var sqlDirectory = `
    SELECT DISTINCT 
      SPLIT(organizational_unit, '/')[SAFE_OFFSET(2)] as region, 
      SPLIT(organizational_unit, '/')[SAFE_OFFSET(3)] as role, 
      target_user 
    FROM ${BQ_TABLE} WHERE organizational_unit IS NOT NULL 
    ORDER BY region, role, target_user
  `;
  var dirData = fetchFromBigQuery(sqlDirectory);
  if (dirData.length === 0) return;

  var descriptionText = "SIGN-OFF LEDGER: This list represents the identified audit scope. Marking an account as 'Approved' confirms that the local manager has verified this user is correct for the upcoming sanitization.\n\n" +
                        "REGISTRE DE VALIDATION : Cette liste représente le périmètre d'audit identifié. Marquer un compte comme 'Approuvé' confirme que le responsable local a vérifié que cet utilisateur est correct pour le nettoyage à venir.";
  
  sheet.getRange("A1:D1").merge().setValue(descriptionText)
       .setBackground(COLOR.brandAccent).setFontColor(COLOR.white).setFontWeight("bold")
       .setWrap(true).setVerticalAlignment("middle").setHorizontalAlignment("center");
  sheet.setRowHeight(1, 85); 

  var headers = ["Region\nRégion", "Role\nRôle", "Managed Account\nCompte Géré", "Validation Status\nStatut de Validation"];
  sheet.getRange(2, 1, 1, 4).setValues([headers]).setBackground(COLOR.darkGrey)
       .setFontColor(COLOR.white).setFontWeight("bold").setWrap(true).setVerticalAlignment("middle").setHorizontalAlignment("center");
  sheet.setRowHeight(2, 45);
  sheet.setFrozenRows(2);

  var processedData = [];
  for (var i = 0; i < dirData.length; i++) {
    var targetAccount = dirData[i][2];
    var preservedStatus = existingStatuses[targetAccount] || "Pending Validation";
    processedData.push([dirData[i][0], dirData[i][1], targetAccount, preservedStatus]);
  }

  var numRows = processedData.length;
  var dataRange = sheet.getRange(3, 1, numRows, 4);
  dataRange.setValues(processedData);
  dataRange.setHorizontalAlignment("center").setVerticalAlignment("middle");
  dataRange.setBorder(true, true, true, true, true, true, COLOR.borderGrey, SpreadsheetApp.BorderStyle.SOLID);
  sheet.getRange(3, 3, numRows, 1).setFontFamily("Courier New").setFontSize(10);

  // Batch set background colors to prevent execution timeouts
  var bgColors = [];
  for (var r = 0; r < numRows; r++) {
    var rowColor = (r % 2 === 0) ? COLOR.white : COLOR.lightBg;
    bgColors.push([rowColor, rowColor, rowColor, rowColor]);
  }
  dataRange.setBackgrounds(bgColors);

  var statusRange = sheet.getRange(3, 4, numRows, 1);
  var dropdownRule = SpreadsheetApp.newDataValidation()
    .requireValueInList(["Pending Validation", "Approved", "Excluded"], true)
    .setAllowInvalid(false).build();
  statusRange.setDataValidation(dropdownRule);

  var rules = [];
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextContains("Pending Validation").setBackground(COLOR.brandAccent).setFontColor(COLOR.white).setBold(true).setRanges([statusRange]).build());
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextContains("Approved").setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setBold(true).setRanges([statusRange]).build());
  rules.push(SpreadsheetApp.newConditionalFormatRule().whenTextContains("Excluded").setBackground(COLOR.alertRed).setFontColor(COLOR.white).setBold(true).setRanges([statusRange]).build());
  sheet.setConditionalFormatRules(rules);

  for (var c = 1; c <= 4; c++) { sheet.autoResizeColumn(c); sheet.setColumnWidth(c, sheet.getColumnWidth(c) + 20); }
}

// ==========================================
// TAB 3: OFFICIAL AUDIT Ledger BUILDER
// ==========================================
function buildAuditLedger(ss) {
  var sheetName = "Official Audit Ledger / Registre d'Audit";
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) { sheet = ss.insertSheet(sheetName, 2); }
  
  if (sheet.getFilter() !== null) {
    sheet.getFilter().remove();
  }
  sheet.clear();
  sheet.clearFormats();
  sheet.clearConditionalFormatRules();
  
  var sqlLedger = `
    SELECT 
      FORMAT_TIMESTAMP('%d/%m/%Y %H:%M', timestamp, '${TIMEZONE}') as formatted_time, 
      SPLIT(organizational_unit, '/')[SAFE_OFFSET(2)] as region, 
      SPLIT(organizational_unit, '/')[SAFE_OFFSET(3)] as role, 
      target_user, 
      file_id, 
      file_name, 
      ROUND(file_size_bytes / 1048576, 2) as size_mb, 
      CAST(is_shared AS STRING), 
      mime_type, 
      action_taken,
      SUBSTR(CAST(created_time AS STRING), 1, 10) as date_created,
      SUBSTR(CAST(modified_time AS STRING), 1, 10) as date_modified
    FROM ${BQ_TABLE} WHERE organizational_unit IS NOT NULL 
    ORDER BY region, role, target_user
  `;
  
  var ledgerData = fetchFromBigQuery(sqlLedger);
  if (ledgerData.length === 0) return;

  var headers = [
    "Timestamp\nHorodatage", "Region\nRégion", "Role\nRôle", "Target Account\nCompte Cible", 
    "File ID\nID du Fichier", "File Name\nNom du Fichier", "File Size (MB)\nTaille (Mo)", 
    "Exposure (Shared)\nExposition", "Document Type\nType de Document", "Status\nStatut", 
    "Error Reason\nRaison de l'Erreur", "Date Created\nDate de Création", "Date Modified\nDate de Modification"
  ];
  
  var mimeMap = {
    'application/vnd.google-apps.document': 'Google Docs',
    'application/vnd.google-apps.spreadsheet': 'Google Sheets',
    'application/vnd.google-apps.presentation': 'Google Slides',
    'application/vnd.google-apps.form': 'Google Forms',
    'application/vnd.google-apps.drawing': 'Google Drawings',
    'application/pdf': 'PDF Document'
  };

  var processedData = [];
  for (var i = 0; i < ledgerData.length; i++) {
    var row = ledgerData[i];
    var rawMime = row[8];
    row[8] = mimeMap[rawMime] || rawMime;
    
    var status = row[9];
    var errorReason = "";
    if (status === "DRY_RUN_SKIPPED") {
      errorReason = "Simulation: File remains intact / Simulation : Le fichier reste intact";
    } else if (status === "VAULT_HOLD") {
      errorReason = "Legal Hold: Bypassed by Google Vault";
    }
    
    // Insert the error reason safely before the date columns
    row.splice(10, 0, errorReason); 
    processedData.push(row);
  }

  var numRows = processedData.length;
  var numCols = headers.length;
  
  var headerRange = sheet.getRange(1, 1, 1, numCols);
  headerRange.setValues([headers]).setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setWrap(true)
             .setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(1, 45);
  sheet.setFrozenRows(1);
  
  var dataRange = sheet.getRange(2, 1, numRows, numCols);
  dataRange.setValues(processedData);
  dataRange.setBorder(true, true, true, true, true, true, COLOR.borderGrey, SpreadsheetApp.BorderStyle.SOLID);
  dataRange.setHorizontalAlignment("center").setVerticalAlignment("middle");
  
  // Batch format backgrounds
  var bgColors = [];
  for (var r = 0; r < numRows; r++) {
    var rowColor = (r % 2 === 0) ? COLOR.white : COLOR.lightBg;
    var rowArray = [];
    for(var c=0; c<numCols; c++){ rowArray.push(rowColor); }
    bgColors.push(rowArray);
  }
  dataRange.setBackgrounds(bgColors);

  sheet.getRange(2, 5, numRows, 1).setFontFamily("Courier New").setFontSize(9); 
  sheet.getDataRange().createFilter();

  var statusRange = sheet.getRange(2, 10, numRows, 2); 
  var rules = [];
  var ruleSimulation = SpreadsheetApp.newConditionalFormatRule()
    .whenTextContains("Simulation") 
    .setBackground(COLOR.brandAccent).setFontColor(COLOR.white).setBold(true).setRanges([statusRange]).build();
    
  rules.push(ruleSimulation);
  sheet.setConditionalFormatRules(rules);

  for (var c = 1; c <= numCols; c++) { sheet.autoResizeColumn(c); }
}

// ==========================================
// TAB 4: SECURITY RISK EXPOSURES BUILDER
// ==========================================
function buildSecurityExposures(ss) {
  var sheetName = "Security Risk Exposures / Risques de Sécurité";
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) { sheet = ss.insertSheet(sheetName, 3); }
  
  if (sheet.getFilter() !== null) {
    sheet.getFilter().remove();
  }
  sheet.clear();
  sheet.clearFormats();
  sheet.clearConditionalFormatRules();
  
  var sqlRisk = `
    SELECT 
      FORMAT_TIMESTAMP('%d/%m/%Y %H:%M', timestamp, '${TIMEZONE}') as formatted_time,
      SPLIT(organizational_unit, '/')[SAFE_OFFSET(2)] as region, 
      target_user, 
      file_id, 
      file_name, 
      mime_type,
      shared_with_emails
    FROM ${BQ_TABLE} 
    WHERE organizational_unit IS NOT NULL AND is_shared = TRUE
    ORDER BY region, target_user
  `;
  
  var riskData = fetchFromBigQuery(sqlRisk);
  
  var descriptionText = "SECURITY EXPOSURE LOG: This ledger identifies files flagged as shared externally or accessible beyond the direct file owner. Immediate review is advised to ensure compliance with corporate data protection and access control policies.\n\n" +
                        "REGISTRE D'EXPOSITION DE SÉCURITÉ : Ce registre identifie les fichiers signalés comme partagés en externe ou accessibles au-delà du propriétaire direct. Un examen immédiat est conseillé pour garantir la conformité aux politiques de protection des données et de contrôle d'accès de l'entreprise.";
  
  sheet.getRange("A1:H1").merge().setValue(descriptionText)
       .setBackground(COLOR.alertRed).setFontColor(COLOR.white).setFontWeight("bold")
       .setWrap(true).setVerticalAlignment("middle").setHorizontalAlignment("center");
  sheet.setRowHeight(1, 85); 

  var headers = [
    "Timestamp\nHorodatage", "Region\nRégion", "Target Account\nCompte Cible", 
    "File ID\nID du Fichier", "File Name\nNom du Fichier", "Document Type\nType de Document", 
    "Exposed Accounts\nComptes Exposés", "Severity\nSévérité"
  ];
  
  if (riskData.length === 0) {
    sheet.getRange(2, 1, 1, 8).setValues([headers]).setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setWrap(true).setHorizontalAlignment("center").setVerticalAlignment("middle");
    sheet.getRange("A3:H3").merge().setValue("NO SECURITY EXPOSURES DETECTED / AUCUNE EXPOSITION DÉTECTÉE").setHorizontalAlignment("center").setFontWeight("bold");
    return;
  }

  var mimeMap = {
    'application/vnd.google-apps.document': 'Google Docs',
    'application/vnd.google-apps.spreadsheet': 'Google Sheets',
    'application/vnd.google-apps.presentation': 'Google Slides',
    'application/vnd.google-apps.form': 'Google Forms',
    'application/vnd.google-apps.drawing': 'Google Drawings',
    'application/pdf': 'PDF Document'
  };

  var processedData = [];
  for (var i = 0; i < riskData.length; i++) {
    var row = riskData[i];
    var rawMime = row[5];
    row[5] = mimeMap[rawMime] || rawMime;
    row.push("High Risk / Risque Élevé");
    processedData.push(row);
  }

  var numRows = processedData.length;
  var numCols = headers.length;
  
  var headerRange = sheet.getRange(2, 1, 1, numCols);
  headerRange.setValues([headers]).setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setWrap(true)
             .setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(2, 45);
  sheet.setFrozenRows(2);
  
  var dataRange = sheet.getRange(3, 1, numRows, numCols);
  dataRange.setValues(processedData);
  dataRange.setBorder(true, true, true, true, true, true, COLOR.borderGrey, SpreadsheetApp.BorderStyle.SOLID);
  dataRange.setHorizontalAlignment("center").setVerticalAlignment("middle");
  
  // Batch format backgrounds
  var bgColors = [];
  for (var r = 0; r < numRows; r++) {
    var rowColor = (r % 2 === 0) ? COLOR.white : COLOR.lightBg;
    var rowArray = [];
    for(var c=0; c<numCols; c++){ rowArray.push(rowColor); }
    bgColors.push(rowArray);
  }
  dataRange.setBackgrounds(bgColors);

  sheet.getRange(3, 4, numRows, 1).setFontFamily("Courier New").setFontSize(9); 
  sheet.getRange(2, 1, numRows + 1, numCols).createFilter();

  var severityRange = sheet.getRange(3, 8, numRows, 1);
  var rules = [];
  var ruleAlert = SpreadsheetApp.newConditionalFormatRule()
    .whenTextContains("High") 
    .setBackground(COLOR.alertRed).setFontColor(COLOR.white).setBold(true).setRanges([severityRange]).build();
  rules.push(ruleAlert);
  sheet.setConditionalFormatRules(rules);

  for (var c = 1; c <= numCols; c++) { sheet.autoResizeColumn(c); }
}

// ==========================================
// TAB 5: EXTERNAL THREATS (DLP HIT LIST) BUILDER
// ==========================================
function buildExternalThreats(ss) {
  var sheetName = "CRITICAL: External Threats / Menaces Externes";
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) { sheet = ss.insertSheet(sheetName, 4); }
  
  if (sheet.getFilter() !== null) {
    sheet.getFilter().remove();
  }
  sheet.clear();
  sheet.clearFormats();
  sheet.clearConditionalFormatRules();
  
  var sqlRisk = `
    SELECT 
      FORMAT_TIMESTAMP('%d/%m/%Y %H:%M', timestamp, '${TIMEZONE}') as formatted_time,
      SPLIT(organizational_unit, '/')[SAFE_OFFSET(2)] as region, 
      target_user, 
      file_id, 
      file_name, 
      mime_type,
      shared_with_emails
    FROM ${BQ_TABLE} 
    WHERE organizational_unit IS NOT NULL AND is_shared = TRUE
    ORDER BY region, target_user
  `;
  
  var riskData = fetchFromBigQuery(sqlRisk);
  
  var descriptionText = "DATA LOSS PREVENTION (DLP) ALERTS: This ledger strictly isolates EXTERNAL sharing. These files are accessible by external domains and represent critical data exfiltration risks requiring immediate remediation.\n\n" +
                        "ALERTES DLP : Ce registre isole strictement le partage EXTERNE. Ces fichiers sont accessibles par des domaines externes et représentent des risques critiques nécessitant une remédiation immédiate.";
  
  var darkRed = "#8B0000"; 
  
  sheet.getRange("A1:H1").merge().setValue(descriptionText)
       .setBackground(darkRed).setFontColor(COLOR.white).setFontWeight("bold")
       .setWrap(true).setVerticalAlignment("middle").setHorizontalAlignment("center");
  sheet.setRowHeight(1, 85); 

  var headers = [
    "Timestamp\nHorodatage", "Region\nRégion", "Target Account\nCompte Cible", 
    "File ID\nID du Fichier", "File Name\nNom du Fichier", "Document Type\nType de Document", 
    "External Domains ONLY\nDomaines Externes UNIQUEMENT", "Severity\nSévérité"
  ];
  
  var mimeMap = {
    'application/vnd.google-apps.document': 'Google Docs',
    'application/vnd.google-apps.spreadsheet': 'Google Sheets',
    'application/vnd.google-apps.presentation': 'Google Slides',
    'application/vnd.google-apps.form': 'Google Forms',
    'application/vnd.google-apps.drawing': 'Google Drawings',
    'application/pdf': 'PDF Document'
  };

  var processedData = [];
  
  for (var i = 0; i < riskData.length; i++) {
    var row = riskData[i];
    var rawMime = row[5];
    row[5] = mimeMap[rawMime] || rawMime;
    
    var rawEmails = row[6];
    var externalEmails = [];
    
    if (rawEmails) {
      var emailArray = String(rawEmails).split(',');
      for (var j = 0; j < emailArray.length; j++) {
        var email = emailArray[j].trim();
        // Isolates emails that are NOT part of the internal corporate domain
        if (email.length > 0 && email.toLowerCase().indexOf(INTERNAL_DOMAIN) === -1) {
          externalEmails.push(email);
        }
      }
    }
    
    if (externalEmails.length > 0) {
      row[6] = externalEmails.join(', '); 
      row.push("CRITICAL BREACH"); 
      processedData.push(row);
    }
  }

  var numRows = processedData.length;
  var numCols = headers.length;
  
  if (numRows === 0) {
    sheet.getRange(2, 1, 1, 8).setValues([headers]).setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setWrap(true).setHorizontalAlignment("center").setVerticalAlignment("middle");
    sheet.getRange("A3:H3").merge().setValue("NO EXTERNAL THREATS DETECTED / AUCUNE MENACE EXTERNE DÉTECTÉE").setHorizontalAlignment("center").setFontWeight("bold").setBackground("#D4EDDA").setFontColor("#155724");
    return;
  }

  var headerRange = sheet.getRange(2, 1, 1, numCols);
  headerRange.setValues([headers]).setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setWrap(true)
             .setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(2, 45);
  sheet.setFrozenRows(2);
  
  var dataRange = sheet.getRange(3, 1, numRows, numCols);
  dataRange.setValues(processedData);
  dataRange.setBorder(true, true, true, true, true, true, COLOR.borderGrey, SpreadsheetApp.BorderStyle.SOLID);
  dataRange.setHorizontalAlignment("center").setVerticalAlignment("middle");
  
  var bgColors = [];
  for (var r = 0; r < numRows; r++) {
    var rowColor = (r % 2 === 0) ? COLOR.white : COLOR.lightBg;
    var rowArray = [];
    for(var c=0; c<numCols; c++){ rowArray.push(rowColor); }
    bgColors.push(rowArray);
  }
  dataRange.setBackgrounds(bgColors);

  sheet.getRange(3, 4, numRows, 1).setFontFamily("Courier New").setFontSize(9); 
  sheet.getRange(2, 1, numRows + 1, numCols).createFilter();

  var severityRange = sheet.getRange(3, 8, numRows, 1);
  var rules = [];
  var ruleAlert = SpreadsheetApp.newConditionalFormatRule()
    .whenTextContains("CRITICAL") 
    .setBackground(COLOR.alertRed).setFontColor(COLOR.white).setBold(true).setRanges([severityRange]).build();
  rules.push(ruleAlert);
  sheet.setConditionalFormatRules(rules);

  for (var c = 1; c <= numCols; c++) { sheet.autoResizeColumn(c); }
}

// ==========================================
// TAB 6: SHADOW IT & MALWARE RISK BUILDER
// ==========================================
function buildShadowITRisk(ss) {
  var sheetName = "Shadow IT & Executables / Informatique Fantôme";
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) { sheet = ss.insertSheet(sheetName, 5); }
  
  if (sheet.getFilter() !== null) {
    sheet.getFilter().remove();
  }
  sheet.clear();
  sheet.clearFormats();
  sheet.clearConditionalFormatRules();
  
  var sqlFiles = `
    SELECT 
      FORMAT_TIMESTAMP('%d/%m/%Y %H:%M', timestamp, '${TIMEZONE}') as formatted_time,
      SPLIT(organizational_unit, '/')[SAFE_OFFSET(2)] as region, 
      target_user, 
      file_id, 
      file_name,
      ROUND(file_size_bytes / 1048576, 2) as size_mb, 
      mime_type
    FROM ${BQ_TABLE} 
    WHERE organizational_unit IS NOT NULL 
    ORDER BY region, target_user
  `;
  
  var fileData = fetchFromBigQuery(sqlFiles);
  
  var descriptionText = "MALWARE & SHADOW IT HUNTING: This ledger automatically flags executable files (.exe, .bat, .apk, .ps1, etc.) stored in user drives. These files represent an unapproved software risk or potential malware hosting vector.\n\n" +
                        "RECHERCHE DE MALWARES ET INFORMATIQUE FANTÔME : Ce registre signale automatiquement les fichiers exécutables stockés. Ces fichiers représentent un risque de logiciel non approuvé ou un vecteur potentiel d'hébergement de malwares.";
  
  var threatGrey = "#1A1A1A"; 
  
  sheet.getRange("A1:H1").merge().setValue(descriptionText)
       .setBackground(threatGrey).setFontColor(COLOR.white).setFontWeight("bold")
       .setWrap(true).setVerticalAlignment("middle").setHorizontalAlignment("center");
  sheet.setRowHeight(1, 85); 

  var headers = [
    "Timestamp\nHorodatage", "Region\nRégion", "Target Account\nCompte Cible", 
    "File ID\nID du Fichier", "File Name\nNom du Fichier", "File Size (MB)\nTaille (Mo)", 
    "Document Type\nType de Document", "Risk Level\nNiveau de Risque"
  ];
  
  var processedData = [];
  
  // REGEX to catch dangerous extensions (case insensitive)
  var execRegex = /\.(exe|bat|ps1|apk|sh|msi|cmd|vbs|bin)$/i;
  
  for (var i = 0; i < fileData.length; i++) {
    var row = fileData[i];
    var fileName = row[4];
    
    // Check if the file name exists and if it matches our executable list
    if (fileName && execRegex.test(String(fileName))) {
      row.push("MALWARE / SHADOW IT"); // Add severity to the end
      processedData.push(row);
    }
  }

  var numRows = processedData.length;
  var numCols = headers.length;
  
  if (numRows === 0) {
    sheet.getRange(2, 1, 1, 8).setValues([headers]).setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setWrap(true).setHorizontalAlignment("center").setVerticalAlignment("middle");
    sheet.getRange("A3:H3").merge().setValue("NO EXECUTABLE THREATS DETECTED / AUCUNE MENACE EXÉCUTABLE DÉTECTÉE").setHorizontalAlignment("center").setFontWeight("bold").setBackground("#D4EDDA").setFontColor("#155724");
    return;
  }

  var headerRange = sheet.getRange(2, 1, 1, numCols);
  headerRange.setValues([headers]).setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setWrap(true)
             .setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(2, 45);
  sheet.setFrozenRows(2);
  
  var dataRange = sheet.getRange(3, 1, numRows, numCols);
  dataRange.setValues(processedData);
  dataRange.setBorder(true, true, true, true, true, true, COLOR.borderGrey, SpreadsheetApp.BorderStyle.SOLID);
  dataRange.setHorizontalAlignment("center").setVerticalAlignment("middle");
  
  var bgColors = [];
  for (var r = 0; r < numRows; r++) {
    var rowColor = (r % 2 === 0) ? COLOR.white : COLOR.lightBg;
    var rowArray = [];
    for(var c=0; c<numCols; c++){ rowArray.push(rowColor); }
    bgColors.push(rowArray);
  }
  dataRange.setBackgrounds(bgColors);

  sheet.getRange(3, 4, numRows, 1).setFontFamily("Courier New").setFontSize(9); 
  sheet.getRange(2, 1, numRows + 1, numCols).createFilter();

  var severityRange = sheet.getRange(3, 8, numRows, 1);
  var rules = [];
  var ruleAlert = SpreadsheetApp.newConditionalFormatRule()
    .whenTextContains("MALWARE") 
    .setBackground(COLOR.darkGrey).setFontColor(COLOR.brandAccent).setBold(true).setRanges([severityRange]).build();
  rules.push(ruleAlert);
  sheet.setConditionalFormatRules(rules);

  for (var c = 1; c <= numCols; c++) { sheet.autoResizeColumn(c); }
}