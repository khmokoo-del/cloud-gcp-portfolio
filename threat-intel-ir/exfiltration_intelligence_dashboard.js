/**
 * Project: Workspace_Exfiltration_Intelligence_Feed
 * Description: 5-Tiered BI Dashboard separating Drive and Gmail exfiltration, 
 * aggregating regional risks, and identifying top internal and external offenders.
 * Author: Khutso
 */

// ==========================================
// ENTERPRISE CONSTANTS & PALETTE
// ==========================================
const PROJECT_ID = 'your-gcp-project-id';

// Points directly to the deduplicated Enterprise View to prevent race conditions
const BQ_TABLE = `\`your-gcp-project-id.compliance_dataset.shadow_audit_log_clean_view\``; 

const COLOR = {
  brandOrange: "#ED7034",
  darkGrey: "#2C3E50",
  lightBg: "#F8F9FA",
  borderGrey: "#E0E0E0",
  alertRed: "#8B0000", 
  white: "#FFFFFF"
};

// ==========================================
// UI INITIALIZATION
// ==========================================
function onOpen() {
  var ui = SpreadsheetApp.getUi();
  ui.createMenu('Threat Intelligence')
      .addItem('Generate Exfiltration Report', 'executeETLPipeline')
      .addToUi();
}

// ==========================================
// MASTER ORCHESTRATOR (ETL)
// ==========================================
function executeETLPipeline() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  ss.toast("Connecting to BigQuery Exfiltration Engine...", "Pipeline Active", 5);

  try {
    var tz = ss.getSpreadsheetTimeZone(); // Dynamic timezone extraction
    
    buildExecutiveSummary(ss);
    buildDriveLedger(ss, tz);
    buildGmailLedger(ss, tz);
    buildRegionalMatrix(ss);
    buildHighestLeakers(ss);
    
    // Cleanup old redundant tabs (Backward iteration to prevent index shifting)
    var validTabs = [
      "1. Executive Summary", 
      "2. Drive Exfiltrations", 
      "3. Gmail Exfiltrations", 
      "4. Regional Risk Matrix", 
      "5. Highest Leakers"
    ];
    
    var sheets = ss.getSheets();
    for (var i = sheets.length - 1; i >= 0; i--) {
      if (validTabs.indexOf(sheets[i].getName()) === -1) {
        ss.deleteSheet(sheets[i]);
      }
    }
    
    ss.toast("Threat intelligence successfully synchronized.", "Execution Complete", 5);
    
  } catch (err) {
    SpreadsheetApp.getUi().alert('System Error: Pipeline failed. Details: ' + err.toString());
  }
}

// ==========================================
// HELPER: BIGQUERY ASYNC EXECUTION
// ==========================================
function fetchFromBigQuery(sql) {
  // Use asynchronous job insertion to prevent Apps Script timeouts
  var job = {
    configuration: {
      query: {
        query: sql,
        useLegacySql: false
      }
    },
    jobReference: {
      location: 'US' // Adjust to your GCP location
    }
  };
  
  var insertResults = BigQuery.Jobs.insert(job, PROJECT_ID);
  var jobId = insertResults.jobReference.jobId;
  var jobLocation = insertResults.jobReference.location;
  
  var queryResults = BigQuery.Jobs.getQueryResults(PROJECT_ID, jobId, {location: jobLocation});
  var sleepTimeMs = 500;
  
  while (!queryResults.jobComplete) {
    Utilities.sleep(sleepTimeMs);
    sleepTimeMs *= 2;
    queryResults = BigQuery.Jobs.getQueryResults(PROJECT_ID, jobId, {location: jobLocation});
  }
  
  var rows = queryResults.rows || [];
  var pageToken = queryResults.pageToken;
  
  while (pageToken) {
    var pageResults = BigQuery.Jobs.getQueryResults(PROJECT_ID, jobId, {
      location: jobLocation, 
      pageToken: pageToken
    });
    
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
      rowData.push(cols[j].v);
    }
    data.push(rowData);
  }
  return data;
}

// ==========================================
// TAB 1: EXECUTIVE SUMMARY
// ==========================================
function buildExecutiveSummary(ss) {
  var sheetName = "1. Executive Summary";
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) { sheet = ss.insertSheet(sheetName, 0); }
  sheet.clear();
  
  var sqlMetrics = `
    SELECT 
      COUNT(DISTINCT target_user), 
      COUNTIF(drive_type != 'Gmail Inbox'), 
      COUNTIF(drive_type = 'Gmail Inbox'), 
      COUNT(file_id) 
    FROM ${BQ_TABLE} WHERE organizational_unit IS NOT NULL
  `;
  var metricsData = fetchFromBigQuery(sqlMetrics);
  if (metricsData.length === 0) return;

  sheet.getRange("A1:D1").merge().setValue("DATA EXFILTRATION INTELLIGENCE: EXECUTIVE SUMMARY")
       .setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold")
       .setHorizontalAlignment("center").setVerticalAlignment("middle").setFontSize(14);
  sheet.setRowHeight(1, 40);

  var execDescription = "This dashboard tracks critical data exfiltration vectors, isolating instances where corporate data has been shared with or emailed to unauthorized external domains.";
  sheet.getRange("A2:D2").merge().setValue(execDescription)
       .setBackground(COLOR.lightBg).setFontColor(COLOR.alertRed).setFontStyle("italic").setFontWeight("bold")
       .setHorizontalAlignment("center").setVerticalAlignment("middle").setWrap(true);
  sheet.setRowHeight(2, 70);
  
  var scoreHeaders = [
    "Monitored Accounts", 
    "Drive Files Compromised", 
    "External Emails Flagged", 
    "Total Critical Exposures"
  ];
  sheet.getRange(4, 1, 1, 4).setValues([scoreHeaders]).setBackground(COLOR.alertRed)
       .setFontColor(COLOR.white).setFontWeight("bold").setWrap(true).setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(4, 50);
  
  sheet.getRange(5, 1, 1, 4).setValues(metricsData).setFontSize(24).setFontWeight("bold")
       .setHorizontalAlignment("center").setVerticalAlignment("middle").setBackground(COLOR.lightBg);
  sheet.setRowHeight(5, 70);
  
  // Batched column resize
  sheet.autoResizeColumns(1, 4);
  for(var c=1; c<=4; c++) { sheet.setColumnWidth(c, sheet.getColumnWidth(c) + 60); }
}

// ==========================================
// TAB 2: DRIVE EXFILTRATION LEDGER
// ==========================================
function buildDriveLedger(ss, tz) {
  var sheetName = "2. Drive Exfiltrations";
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) { sheet = ss.insertSheet(sheetName, 1); }
  sheet.clear(); sheet.clearFormats();
  
  var sql = `
    SELECT 
      FORMAT_TIMESTAMP('%d/%m/%Y %H:%M', timestamp, '${tz}') as formatted_time,
      ARRAY_REVERSE(SPLIT(organizational_unit, '/'))[SAFE_OFFSET(1)] as region, 
      target_user, drive_type, file_name, mime_type, shared_with_emails
    FROM ${BQ_TABLE} WHERE organizational_unit IS NOT NULL AND drive_type != 'Gmail Inbox'
    ORDER BY timestamp DESC LIMIT 1000
  `;
  var data = fetchFromBigQuery(sql);
  
  sheet.getRange("A1:G1").merge().setValue("GOOGLE DRIVE INCIDENT RESPONSE LEDGER (EXTERNAL PERMISSIONS)")
       .setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(1, 45); 

  var headers = ["Timestamp", "Region", "Target Account", "Drive Type", "File Name", "Document Type", "External Domains Flagged"];
  if (data.length === 0) {
    sheet.getRange("A3:G3").merge().setValue("NO DRIVE EXFILTRATION DETECTED").setHorizontalAlignment("center").setFontWeight("bold");
    return;
  }

  var mimeMap = {
    'application/vnd.google-apps.document': 'Google Docs',
    'application/vnd.google-apps.spreadsheet': 'Google Sheets',
    'application/vnd.google-apps.presentation': 'Google Slides',
    'application/vnd.google-apps.form': 'Google Forms',
    'application/pdf': 'PDF Document'
  };
  for (var i = 0; i < data.length; i++) {
    data[i][5] = mimeMap[data[i][5]] || data[i][5];
  }

  sheet.getRange(2, 1, 1, headers.length).setValues([headers]).setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setHorizontalAlignment("center");
  sheet.getRange(3, 1, data.length, headers.length).setValues(data).setBorder(true, true, true, true, true, true, COLOR.borderGrey, SpreadsheetApp.BorderStyle.SOLID).setHorizontalAlignment("center");
  sheet.getRange(3, 7, data.length, 1).setFontColor(COLOR.alertRed).setFontWeight("bold");
  
  // Batched column resize
  sheet.autoResizeColumns(1, headers.length);
  sheet.setColumnWidth(5, 300); 
}

// ==========================================
// TAB 3: GMAIL EXFILTRATION LEDGER
// ==========================================
function buildGmailLedger(ss, tz) {
  var sheetName = "3. Gmail Exfiltrations";
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) { sheet = ss.insertSheet(sheetName, 2); }
  sheet.clear(); sheet.clearFormats();
  
  var sql = `
    SELECT 
      FORMAT_TIMESTAMP('%d/%m/%Y %H:%M', timestamp, '${tz}') as formatted_time,
      ARRAY_REVERSE(SPLIT(organizational_unit, '/'))[SAFE_OFFSET(1)] as region, 
      target_user, file_name, shared_with_emails
    FROM ${BQ_TABLE} WHERE organizational_unit IS NOT NULL AND drive_type = 'Gmail Inbox'
    ORDER BY timestamp DESC LIMIT 1000
  `;
  var data = fetchFromBigQuery(sql);
  
  sheet.getRange("A1:E1").merge().setValue("GMAIL INCIDENT RESPONSE LEDGER (ATTACHMENTS SENT TO EXTERNAL DOMAINS)")
       .setBackground(COLOR.brandOrange).setFontColor(COLOR.white).setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(1, 45); 

  var headers = ["Timestamp", "Region", "Sender Account", "Email Subject Line", "External Recipients Flagged"];
  if (data.length === 0) {
    sheet.getRange("A3:E3").merge().setValue("NO GMAIL EXFILTRATION DETECTED").setHorizontalAlignment("center").setFontWeight("bold");
    return;
  }

  sheet.getRange(2, 1, 1, headers.length).setValues([headers]).setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setHorizontalAlignment("center");
  sheet.getRange(3, 1, data.length, headers.length).setValues(data).setBorder(true, true, true, true, true, true, COLOR.borderGrey, SpreadsheetApp.BorderStyle.SOLID).setHorizontalAlignment("center");
  sheet.getRange(3, 5, data.length, 1).setFontColor(COLOR.alertRed).setFontWeight("bold");
  
  // Batched column resize
  sheet.autoResizeColumns(1, headers.length);
  sheet.setColumnWidth(4, 400); 
}

// ==========================================
// TAB 4: REGIONAL RISK MATRIX
// ==========================================
function buildRegionalMatrix(ss) {
  var sheetName = "4. Regional Risk Matrix";
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) { sheet = ss.insertSheet(sheetName, 3); }
  sheet.clear(); sheet.clearFormats();
  
  var sql = `
    SELECT 
      ARRAY_REVERSE(SPLIT(organizational_unit, '/'))[SAFE_OFFSET(1)] as region, 
      COUNT(DISTINCT CASE WHEN LOWER(ARRAY_REVERSE(SPLIT(organizational_unit, '/'))[SAFE_OFFSET(0)]) LIKE '%agent%' THEN target_user END) as agents,
      COUNT(DISTINCT CASE WHEN LOWER(ARRAY_REVERSE(SPLIT(organizational_unit, '/'))[SAFE_OFFSET(0)]) LIKE '%supervisor%' THEN target_user END) as supervisors,
      COUNTIF(drive_type != 'Gmail Inbox') as drive_breaches,
      COUNTIF(drive_type = 'Gmail Inbox') as email_breaches,
      COUNT(file_id) as total_incidents
    FROM ${BQ_TABLE} WHERE organizational_unit IS NOT NULL 
    GROUP BY region ORDER BY total_incidents DESC
  `;
  var data = fetchFromBigQuery(sql);
  
  sheet.getRange("A1:F1").merge().setValue("REGIONAL THREAT AGGREGATION")
       .setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(1, 45); 

  var headers = ["Region", "Compromised Agents", "Compromised Supervisors", "Drive Exfiltrations", "Email Exfiltrations", "Total Regional Incidents"];
  if (data.length === 0) return;

  sheet.getRange(2, 1, 1, headers.length).setValues([headers]).setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setHorizontalAlignment("center");
  sheet.getRange(3, 1, data.length, headers.length).setValues(data).setBorder(true, true, true, true, true, true, COLOR.borderGrey, SpreadsheetApp.BorderStyle.SOLID).setHorizontalAlignment("center");
  sheet.getRange(3, 6, data.length, 1).setBackground(COLOR.alertRed).setFontColor(COLOR.white).setFontWeight("bold");
  
  // Batched column resize
  sheet.autoResizeColumns(1, headers.length);
  for (var c = 1; c <= headers.length; c++) { sheet.setColumnWidth(c, sheet.getColumnWidth(c) + 20); }
}

// ==========================================
// TAB 5: HIGHEST LEAKERS
// ==========================================
function buildHighestLeakers(ss) {
  var sheetName = "5. Highest Leakers";
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) { sheet = ss.insertSheet(sheetName, 4); }
  sheet.clear(); sheet.clearFormats();
  
  var sqlInternal = `
    SELECT 
      target_user, 
      ARRAY_REVERSE(SPLIT(MAX(organizational_unit), '/'))[SAFE_OFFSET(1)] as region,
      COUNTIF(drive_type != 'Gmail Inbox') as drive_breaches,
      COUNTIF(drive_type = 'Gmail Inbox') as email_breaches,
      COUNT(file_id) as total_breaches
    FROM ${BQ_TABLE} WHERE organizational_unit IS NOT NULL 
    GROUP BY target_user ORDER BY total_breaches DESC LIMIT 15
  `;
  var internalData = fetchFromBigQuery(sqlInternal);
  
  // Implicit CROSS JOIN Data Loss fixed with LEFT JOIN UNNEST
  var sqlExternal = `
    SELECT 
      TRIM(ext_email) as receiving_domain,
      COUNT(file_id) as total_exfiltrations
    FROM ${BQ_TABLE}
    LEFT JOIN UNNEST(SPLIT(shared_with_emails, ',')) as ext_email
    WHERE TRIM(ext_email) != '' AND TRIM(ext_email) NOT LIKE 'From:%' AND LOWER(ext_email) NOT LIKE '%your-domain.com%'
    GROUP BY receiving_domain ORDER BY total_exfiltrations DESC LIMIT 15
  `;
  var externalData = fetchFromBigQuery(sqlExternal);
  
  sheet.getRange("A1:E1").merge().setValue("TOP 15 INTERNAL OFFENDERS")
       .setBackground(COLOR.alertRed).setFontColor(COLOR.white).setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(1, 40); 
  var intHeaders = ["Internal Account", "Region", "Drive Leaks", "Gmail Leaks", "Total Severity"];
  sheet.getRange(2, 1, 1, 5).setValues([intHeaders]).setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setHorizontalAlignment("center");
  if (internalData.length > 0) {
    sheet.getRange(3, 1, internalData.length, 5).setValues(internalData).setBorder(true, true, true, true, true, true, COLOR.borderGrey, SpreadsheetApp.BorderStyle.SOLID).setHorizontalAlignment("center");
    sheet.getRange(3, 5, internalData.length, 1).setFontWeight("bold");
  }

  sheet.getRange("G1:H1").merge().setValue("TOP 15 EXTERNAL RECEIVERS")
       .setBackground(COLOR.brandOrange).setFontColor(COLOR.white).setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
  var extHeaders = ["External Domain / Email", "Total Files/Emails Received"];
  sheet.getRange(2, 7, 1, 2).setValues([extHeaders]).setBackground(COLOR.darkGrey).setFontColor(COLOR.white).setFontWeight("bold").setHorizontalAlignment("center");
  if (externalData.length > 0) {
    sheet.getRange(3, 7, externalData.length, 2).setValues(externalData).setBorder(true, true, true, true, true, true, COLOR.borderGrey, SpreadsheetApp.BorderStyle.SOLID).setHorizontalAlignment("center");
    sheet.getRange(3, 8, externalData.length, 1).setFontWeight("bold");
  }

  // Batched column resize
  sheet.autoResizeColumns(1, 8);
  for (var c = 1; c <= 8; c++) { sheet.setColumnWidth(c, sheet.getColumnWidth(c) + 20); }
  sheet.setColumnWidth(6, 40); 
}
