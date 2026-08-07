```javascript
/**
 * ENTERPRISE SECURITY POSTURE MANAGEMENT (CSPM) - 
 * Architecture: 4-Phase Chained Orchestrator | LockService Concurrency Protection
 * Subsystems: Dual-Verification (Hostname + Hardware Serial) for EDR Coverage
 */

// === 1. CORE ENTERPRISE CONFIGURATION ===
const scriptProps = PropertiesService.getScriptProperties();
const JC_API_KEY = scriptProps.getProperty('JC_API_KEY') || 'YOUR_JC_KEY';
const ESET_API_USER = scriptProps.getProperty('ESET_API_USER') || 'YOUR_ESET_USER';
const ESET_API_PASS = scriptProps.getProperty('ESET_API_PASS') || 'YOUR_ESET_PASS';
const LA_API_KEY = scriptProps.getProperty('LA_API_KEY') || 'YOUR_LA_KEY';

const PROJECT_ID = 'your-gcp-project-id'; 
const DATASET_ID = 'endpoint_compliance';
const REGION = 'eu'; 
const APP_NAME = "Enterprise Security Posture Management";

// Brand Identity
const BRAND_PRIMARY = "#E86C20";   
const BRAND_SECONDARY = "#222222"; 
const BRAND_TERTIARY = "#333333"; 
const URL_LOGO = "https://your-enterprise-domain.com/dark-theme-logo.png";

const WATCHLIST = {
  TIER_1: ['tor browser', 'bittorrent', 'utorrent', 'nordvpn', 'expressvpn', 'mega.nz'],
  TIER_2: ['anydesk', 'teamviewer', 'logmein', 'ammyy'],
  TIER_3: ['steam', 'epic games', 'minecraft', 'roblox', 'origin', 'firefox', 'mozilla']
};
const BAD_EXTENSIONS = ['hola', 'hoxx', 'touch vpn', 'setupvpn', 'zenmate'];
const OS_BASELINES = { macOS_Major: 13, Win_Build: 19045, Chrome_Major: 120 }; 

const MAX_EXECUTION_TIME_MS = 300000; 
let START_TIME;
let securityAnomalies = [];
let jcSystemsCache = [];
let jcUsersCache = [];
let esetDevicesCache = {};
let systemMap = {}; 
let osCountsSummary = {};

// === 2. USER INTERFACE REGISTRATION ===
function onOpen() {
  const ui = SpreadsheetApp.getUi();
  ui.createMenu('Security Posture Management')
      .addItem('Execute Posture Audit (Background)', 'initializeChainedAudit')
      .addSeparator()
      .addItem('Initialize Active Response', 'showSidebar')
      .addItem('Cancel Running Audits', 'abortAllChains')
      .addToUi();
}

// === 3. CHAINED ORCHESTRATOR & LOCK SERVICE ===
function initializeChainedAudit() {
  let lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) {
    SpreadsheetApp.getUi().alert('An audit is already running in the background. Please wait for it to complete or click "Cancel Running Audits".');
    return;
  }
  
  try {
    SpreadsheetApp.getUi().toast("Initiating Phase 1 of 4. You can close this tab; the audit will complete in the background.", "Audit Started", 10);
    scriptProps.setProperty('AUDIT_PHASE', '1');
    clearAuditTriggers();
    auditRouter(); 
  } finally {
    lock.releaseLock();
  }
}

function abortAllChains() {
  clearAuditTriggers();
  scriptProps.deleteProperty('AUDIT_PHASE');
  SpreadsheetApp.getUi().toast("All pending background processes have been terminated.", "Audit Aborted");
}

function clearAuditTriggers() {
  let triggers = ScriptApp.getProjectTriggers();
  for (let i = 0; i < triggers.length; i++) {
    if (triggers[i].getHandlerFunction() === 'auditRouter') ScriptApp.deleteTrigger(triggers[i]);
  }
}

function scheduleNextPhase() {
  clearAuditTriggers();
  ScriptApp.newTrigger('auditRouter').timeBased().after(30000).create(); 
}

// === 4. THE STATE MACHINE ===
function auditRouter() {
  START_TIME = Date.now();
  
  let lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) return;

  try {
    let phase = scriptProps.getProperty('AUDIT_PHASE');
    let ss = SpreadsheetApp.getActiveSpreadsheet();
    if (!ss) return;

    if (phase === '1') {
      populateGlobalCaches();
      let fleetMatrix = evaluateGlobalEndpoints(); 
      let idMatrix = evaluateDirectoryAudit();
      let epMatrix = evaluateEndpointHealth();
      let alertsMatrix = evaluateJumpCloudAlerts();
      let pwMatrix = evaluateExpiringPasswords();
      let geoMatrix = evaluateGeographicDistribution();

      let actionUnencrypted = [epMatrix[0]].concat(epMatrix.filter(r => r[6] === "VULNERABLE FDE"));
      let actionOutdated = [epMatrix[0]].concat(epMatrix.filter(r => r[6] === "OUTDATED OS"));
      let actionInactive = [epMatrix[0]].concat(epMatrix.filter(r => r[6] === "INACTIVE ENDPOINT"));
      let actionUnboundAdmins = [idMatrix[0]].concat(idMatrix.filter(r => r[7] === "ADMIN MISSING MFA"));
      let actionLocalAdmins = [idMatrix[0]].concat(idMatrix.filter(r => r[3] === "Superuser"));

      buildGeoMapTab(ss, "Global Heatmap", geoMatrix, "Geographic distribution of managed endpoints.", "Répartition géographique des terminaux gérés.");
      buildTab(ss, "Global Endpoints", fleetMatrix, buildFleetFormatting, "Comprehensive inventory of hardware.", "Inventaire complet du matériel.");
      buildTab(ss, "Directory Audit", idMatrix, buildDirectoryFormatting, "IAM audit log.", "Journal d'audit IAM.");
      buildTab(ss, "Endpoint Health", epMatrix, buildEndpointFormatting, "Telemetry and compliance status.", "Télémétrie et état de conformité.");
      buildTab(ss, "System Alerts", alertsMatrix, buildAlertsFormatting, "Native security alerts.", "Alertes de sécurité natives.");
      
      buildTab(ss, "Action: Unencrypted FDE", actionUnencrypted, buildActionFormatting, "FDE failures.", "Échecs FDE.");
      buildTab(ss, "Action: Outdated OS", actionOutdated, buildActionFormatting, "OS update required.", "Mise à jour de l'OS requise.");
      buildTab(ss, "Action: Inactive Endpoints", actionInactive, buildActionFormatting, "Dormant hardware.", "Matériel inactif.");
      buildTab(ss, "Action: Unbound Admins", actionUnboundAdmins, buildActionFormatting, "Admins missing MFA.", "Administrateurs sans MFA.");
      buildTab(ss, "Action: Local Admins", actionLocalAdmins, buildActionFormatting, "Elevated local privileges.", "Privilèges locaux élevés.");
      buildTab(ss, "Action: Expiring Passwords", pwMatrix, buildPasswordFormatting, "Expiring passwords.", "Mots de passe expirants.");

      scriptProps.setProperty('AUDIT_PHASE', '2');
      scheduleNextPhase();

    } else if (phase === '2') {
      populateGlobalCaches(); 
      let esetGapsMatrix = evaluateESETCoverage();
      let usbMatrix = evaluateUSBCompliance();
      let threatMatrix = evaluateThreatIntel();
      let watchMatrix = evaluateSoftwareWatchlist();

      buildTab(ss, "Action: EDR Gaps", esetGapsMatrix, buildESETCoverageFormatting, "Missing EDR agents.", "Agents EDR manquants.");
      buildTab(ss, "USB Compliance", usbMatrix, buildUSBFormatting, "Removable media restrictions.", "Restrictions des supports amovibles.");
      buildTab(ss, "Threat Intel", threatMatrix, buildThreatFormatting, "EDR detections.", "Détections EDR.");
      buildTab(ss, "Software Watchlist", watchMatrix, buildWatchlistFormatting, "Unsanctioned software.", "Logiciels non autorisés.");

      scriptProps.setProperty('AUDIT_PHASE', '3');
      scheduleNextPhase();

    } else if (phase === '3') {
      populateGlobalCaches(); 
      let rebootMatrix = evaluateRebootPosture();
      let shadowMatrix = evaluateShadowAdmins();
      let extMatrix = evaluateChromeExtensions();
      let chromeMatrix = evaluateVulnerableChrome();

      buildTab(ss, "Action: Outdated Browsers", chromeMatrix, buildActionFormatting, "Outdated Chrome.", "Chrome obsolète.");
      buildTab(ss, "Action: Pending Reboots", rebootMatrix, buildActionFormatting, "Pending kernel reboots.", "Redémarrages en attente.");
      buildTab(ss, "Action: Shadow Accounts", shadowMatrix, buildActionFormatting, "Shadow admin accounts.", "Comptes administrateurs fantômes.");
      buildTab(ss, "Action: Extensions", extMatrix, buildActionFormatting, "Malicious extensions.", "Extensions malveillantes.");

      scriptProps.setProperty('AUDIT_PHASE', '4');
      scheduleNextPhase();

    } else if (phase === '4') {
      let mfaCount = Math.max(0, (ss.getSheetByName("Action: Unbound Admins")?.getLastRow() || 6) - 6);
      let fdeCount = Math.max(0, (ss.getSheetByName("Action: Unencrypted FDE")?.getLastRow() || 6) - 6);
      let inactiveCount = Math.max(0, (ss.getSheetByName("Action: Inactive Endpoints")?.getLastRow() || 6) - 6);
      let pwCount = Math.max(0, (ss.getSheetByName("Action: Expiring Passwords")?.getLastRow() || 6) - 6);
      let osCount = Math.max(0, (ss.getSheetByName("Action: Outdated OS")?.getLastRow() || 6) - 6);
      let rebootCount = Math.max(0, (ss.getSheetByName("Action: Pending Reboots")?.getLastRow() || 6) - 6);
      let shadowCount = Math.max(0, (ss.getSheetByName("Action: Shadow Accounts")?.getLastRow() || 6) - 6);
      let extCount = Math.max(0, (ss.getSheetByName("Action: Extensions")?.getLastRow() || 6) - 6);
      let chromeCount = Math.max(0, (ss.getSheetByName("Action: Outdated Browsers")?.getLastRow() || 6) - 6);

      populateGlobalCaches(); 
      buildExecutiveSummary(ss, mfaCount, fdeCount, inactiveCount, pwCount, osCount, rebootCount, shadowCount, extCount, chromeCount);
      
      scriptProps.deleteProperty('AUDIT_PHASE');
      clearAuditTriggers();
    }
  } catch (error) {
    console.error(`Chained Execution Exception: ${error.stack}`);
    dispatchPipelineFailureAlert(`Chained Phase failed: ${error.message}`);
    clearAuditTriggers();
    scriptProps.deleteProperty('AUDIT_PHASE');
  } finally {
    lock.releaseLock();
  }
}

// === 5. SYSTEM CACHE MEMORY ===
function populateGlobalCaches() {
  osCountsSummary = {macOS: 0, Windows: 0, Linux: 0, iOS: 0, Android: 0};
  let skip = 0; jcSystemsCache = []; systemMap = {};
  
  while(true) {
    let res = UrlFetchApp.fetch(`https://console.jumpcloud.com/api/systems?limit=100&skip=${skip}`, {headers: {'x-api-key': JC_API_KEY}, muteHttpExceptions: true});
    if (res.getResponseCode() !== 200) break;
    let data = JSON.parse(res.getContentText()).results || [];
    if(data.length === 0) break;
    jcSystemsCache = jcSystemsCache.concat(data);
    data.forEach(s => {
      systemMap[s.id] = s.hostname;
      if(s.osFamily) {
        let os = s.osFamily.toLowerCase();
        if(os.includes("mac") || os.includes("darwin")) osCountsSummary.macOS++;
        else if(os.includes("win")) osCountsSummary.Windows++;
        else if(os.includes("linux") || os.includes("ubuntu")) osCountsSummary.Linux++;
      }
    }); 
    skip += 100;
  }
  
  skip = 0; jcUsersCache = [];
  while(true) {
    let res = UrlFetchApp.fetch(`https://console.jumpcloud.com/api/systemusers?limit=100&skip=${skip}`, {headers: {'x-api-key': JC_API_KEY}, muteHttpExceptions: true});
    if (res.getResponseCode() !== 200) break;
    let data = JSON.parse(res.getContentText()).results || [];
    if(data.length === 0) break;
    jcUsersCache = jcUsersCache.concat(data);
    skip += 100;
  }
  
  let authRes = UrlFetchApp.fetch(`https://${REGION}.business-account.iam.eset.systems/oauth/token`, { method: 'post', payload: { 'grant_type': 'password', 'username': ESET_API_USER, 'password': ESET_API_PASS }, muteHttpExceptions: true});
  if(authRes.getResponseCode() === 200) {
    let token = JSON.parse(authRes.getContentText()).access_token;
    scriptProps.setProperty('TEMP_ESET_TOKEN', token);
    let pageToken = '';
    while(true) {
      let url = `https://${REGION}.device-management.eset.systems/v1/devices?pageSize=1000` + (pageToken ? `&pageToken=${pageToken}` : '');
      let res = UrlFetchApp.fetch(url, {headers: {'Authorization': `Bearer ${token}`}, muteHttpExceptions: true});
      if(res.getResponseCode() !== 200) break;
      let data = JSON.parse(res.getContentText());
      (data.devices || []).forEach(d => { 
        // CACHE UPDATE: Now grabbing hardware serial number from EDR as well for cross-referencing
        let host = d.hostname || d.computerName || d.name || "UNNAMED_EDR_DEVICE";
        let serial = d.serialNumber || (d.hardware ? d.hardware.serialNumber : null);
        esetDevicesCache[d.uuid] = {
            hostname: host,
            serial: serial ? String(serial).toUpperCase().trim() : null
        };
      }); 
      if(!data.nextPageToken) break;
      pageToken = data.nextPageToken;
    }
  }
}

// === 6. POSTURE ENGINES ===
function normalizeHostname(name) { return name ? String(name).toUpperCase().split('.')[0].trim() : "UNKNOWN"; }

function evaluateESETCoverage() {
  let matrix = [["Endpoint", "Hardware Serial Number", "Platform", "Coverage State", "Required Action"]];
  let esetHosts = [];
  let esetSerials = [];

  // Separate EDR names and serials into searchable arrays
  Object.values(esetDevicesCache).forEach(device => {
    if (device.hostname) esetHosts.push(normalizeHostname(device.hostname));
    if (device.serial) esetSerials.push(device.serial);
  });

  jcSystemsCache.forEach(s => {
    let rawHost = s.hostname || "UNKNOWN";
    let hostClean = normalizeHostname(rawHost);
    let jcSerial = s.serialNumber ? String(s.serialNumber).toUpperCase().trim() : "NO_SERIAL";

    let osRaw = s.osFamily ? s.osFamily.toLowerCase() : "unknown";
    let isMac = osRaw.includes("mac") || osRaw.includes("darwin");
    let isWin = osRaw.includes("win");
    let isLinux = osRaw.includes("linux") || osRaw.includes("ubuntu");
    
    // DUAL-VERIFICATION: Match by Hostname OR match by Hardware Serial Number
    let hasESET = esetHosts.includes(hostClean) || (jcSerial !== "NO_SERIAL" && esetSerials.includes(jcSerial));
    
    if ((isMac || isWin) && !hasESET) matrix.push([rawHost.toUpperCase(), jcSerial, isMac ? "macOS" : "Windows", "Missing", "INSTALL EDR"]);
    else if (isLinux && hasESET) matrix.push([rawHost.toUpperCase(), jcSerial, "Linux", "Installed (Prohibited)", "REMOVE EDR"]);
  });
  
  let headers = matrix.shift(); matrix.sort((a, b) => a[4].localeCompare(b[4])); matrix.unshift(headers);
  return matrix;
}

function evaluateGeographicDistribution() {
  let geoCounts = {};
  const countryMap = { "DEU": "Germany", "DE": "Germany", "CAN": "Canada", "CA": "Canada", "CANA": "Canada", "AUS": "Australia", "AU": "Australia", "JPN": "Japan", "JP": "Japan", "BRA": "Brazil", "BR": "Brazil", "MEX": "Mexico", "MX": "Mexico", "IND": "India", "IN": "India", "ITA": "Italy", "IT": "Italy", "ESP": "Spain", "ES": "Spain", "SWE": "Sweden", "SE": "Sweden", "NOR": "Norway", "NO": "Norway", "FIN": "Finland", "FI": "Finland", "CHL": "Chile", "CL": "Chile", "AUSPT": "Australia" };
  jcSystemsCache.forEach(s => {
    let host = s.hostname ? s.hostname.toUpperCase().trim() : "";
    let rawRegion = host.indexOf('-') > 0 ? host.split('-')[0].trim() : host.substring(0, 3);
    let mappedRegion = countryMap[rawRegion] || rawRegion;
    if (mappedRegion.length >= 2 && mappedRegion !== "UNK") geoCounts[mappedRegion] = (geoCounts[mappedRegion] || 0) + 1;
  });
  let matrix = [["Country", "Asset Density"]];
  for (let [country, count] of Object.entries(geoCounts)) matrix.push([country, count]);
  return matrix;
}

function evaluateGlobalEndpoints() {
  let matrix = [["Endpoint", "Hardware Serial Number", "Deployment Zone", "Platform", "Build Kernel", "Latest Telemetry"]];
  jcSystemsCache.forEach(s => {
    let host = s.hostname ? s.hostname.toUpperCase() : "UNKNOWN";
    let serial = s.serialNumber || "N/A"; 
    let region = host.indexOf('-') > 0 ? host.split('-')[0] : "UNKNOWN REGION"; 
    let osRaw = s.osFamily ? s.osFamily.toLowerCase() : "unknown";
    let osClean = osRaw.includes("mac") ? "macOS" : (osRaw.includes("win") ? "Windows" : "Linux");
    matrix.push([host, serial, region, osClean, s.osVersionDetail?.version || s.version || "N/A", s.lastContact ? s.lastContact.split('T')[0] : "Never"]);
  });
  return matrix;
}

function evaluateDirectoryAudit() {
  let matrix = [["Username", "Email", "Directory State", "Privilege Level", "MFA Binding", "Lockout Status", "Password Expiry", "Compliance Posture"]];
  jcUsersCache.forEach(u => {
    let isLocalAdmin = u.sudo || u.administrator;
    let hasMFA = (u.mfa && u.mfa.configured) || (u.mfaEnrollment && u.mfaEnrollment.overallStatus !== "NOT_ENROLLED");
    let violation = "Compliant";
    if (u.suspended) violation = isLocalAdmin ? "HIGH RISK: SUSPENDED ADMIN" : "SUSPENDED"; 
    else if (isLocalAdmin && !hasMFA) { violation = "ADMIN MISSING MFA"; securityAnomalies.push({ target: u.email, issue: "Superuser Missing MFA" }); }
    matrix.push([u.username, u.email, u.suspended ? "Suspended" : "Active", isLocalAdmin ? "Superuser" : "Standard", hasMFA ? "Enrolled" : "Missing", u.account_locked, u.password_expired, violation]);
  });
  return matrix;
}

function evaluateExpiringPasswords() {
  let matrix = [["Username", "Email", "Expiration Date", "Days Remaining"]];
  let now = new Date().getTime();
  jcUsersCache.forEach(u => {
    if (!u.suspended && !u.password_never_expires && u.password_expiration_date) {
      let expDate = new Date(u.password_expiration_date);
      if (!isNaN(expDate.getTime())) {
        let diffDays = Math.ceil((expDate.getTime() - now) / 86400000);
        if (diffDays >= 0 && diffDays <= 14) matrix.push([u.username, u.email, u.password_expiration_date.split('T')[0], diffDays]);
      }
    }
  });
  return matrix;
}

function evaluateEndpointHealth() {
  let matrix = [["Endpoint", "Platform", "Build Kernel", "Volume Encryption", "Latest Telemetry", "Dormancy Delta", "Compliance Posture"]];
  let now = new Date().getTime();
  jcSystemsCache.forEach(s => {
    let osRaw = s.osFamily ? s.osFamily.toLowerCase() : "unknown";
    let buildKernel = s.osVersionDetail?.version || s.version || "0";
    let daysOffline = s.lastContact ? Math.floor((now - new Date(s.lastContact).getTime()) / 86400000) : 999;
    let fdeActive = (s.fde && s.fde.active) ? "SECURED" : "VULNERABLE";
    
    let isOutdated = false;
    if (osRaw.includes("mac")) { if (parseInt(buildKernel.split('.')[0]) < OS_BASELINES.macOS_Major) isOutdated = true; } 
    else if (osRaw.includes("win")) { if (parseInt(buildKernel.split('.').pop()) < OS_BASELINES.Win_Build) isOutdated = true; }

    let flag = "Compliant";
    if (daysOffline >= 90) flag = "INACTIVE ENDPOINT"; 
    else if (fdeActive === "VULNERABLE" && !osRaw.includes("linux")) flag = "VULNERABLE FDE"; 
    else if (isOutdated) flag = "OUTDATED OS"; 

    matrix.push([s.hostname, s.osFamily, buildKernel, fdeActive, s.lastContact?.split('T')[0] || "Never", `${daysOffline} Days`, flag]);
  });
  return matrix;
}

function evaluateRebootPosture() {
  let matrix = [["Endpoint", "Uptime (Days)", "Required Action"]];
  let skip = 0;
  while(true) {
    let res = UrlFetchApp.fetch(`https://console.jumpcloud.com/api/v2/systeminsights/uptime?limit=100&skip=${skip}`, {headers: {'x-api-key': JC_API_KEY}, muteHttpExceptions: true});
    if(res.getResponseCode() !== 200) break;
    let data = JSON.parse(res.getContentText());
    if(data.length === 0) break;
    data.forEach(u => { if(u.days > 30) matrix.push([systemMap[u.system_id] || "Unknown", u.days, "REBOOT REQUIRED"]); });
    skip += 100;
  }
  return matrix;
}

function evaluateVulnerableChrome() {
  let matrix = [["Endpoint", "Browser Software", "Installed Version", "Required Action"]];
  let skip = 0;
  while(true) {
    let res = UrlFetchApp.fetch(`https://console.jumpcloud.com/api/v2/systeminsights/programs?filter=name:($sw:Google Chrome)&limit=100&skip=${skip}`, { headers: { 'x-api-key': JC_API_KEY }, muteHttpExceptions: true });
    if (res.getResponseCode() !== 200) break;
    let data = JSON.parse(res.getContentText());
    if (data.length === 0) break;
    
    data.forEach(p => {
      let majorVer = parseInt(p.version.split('.')[0]) || 0;
      if (majorVer > 0 && majorVer < OS_BASELINES.Chrome_Major) matrix.push([systemMap[p.system_id] || "Unknown Identifier", p.name, p.version, "UPDATE BROWSER"]);
    });
    skip += 100;
  }
  return matrix;
}

function evaluateShadowAdmins() {
  let matrix = [["Endpoint", "Local Account", "UID", "Status"]];
  let managedUsers = jcUsersCache.map(u => u.username.toLowerCase());
  let skip = 0;
  while(true) {
    let res = UrlFetchApp.fetch(`https://console.jumpcloud.com/api/v2/systeminsights/users?limit=100&skip=${skip}`, {headers: {'x-api-key': JC_API_KEY}, muteHttpExceptions: true});
    if(res.getResponseCode() !== 200) break;
    let data = JSON.parse(res.getContentText());
    if(data.length === 0) break;
    data.forEach(u => {
      let uid = parseInt(u.uid);
      let uname = u.username.toLowerCase();
      let isSystemDaemon = uname.startsWith('_') || uname.startsWith('eset-') || ['admin','administrator','guest','defaultaccount','wdagutilityaccount','helpdesk'].includes(uname);
      if(uid >= 500 && uid < 65000 && !managedUsers.includes(uname) && !isSystemDaemon) matrix.push([systemMap[u.system_id] || "Unknown", u.username, uid, "UNMANAGED LOCAL ACCOUNT"]);
    });
    skip += 100;
  }
  return matrix;
}

function evaluateChromeExtensions() {
  let matrix = [["Endpoint", "Browser", "Malicious Extension", "Action"]];
  BAD_EXTENSIONS.forEach(ext => {
    let res = UrlFetchApp.fetch(`https://console.jumpcloud.com/api/v2/systeminsights/chrome_extensions?filter=name:($sw:${encodeURIComponent(ext)})`, { headers: { 'x-api-key': JC_API_KEY }, muteHttpExceptions: true });
    if (res.getResponseCode() === 200) JSON.parse(res.getContentText()).forEach(e => matrix.push([systemMap[e.system_id] || "Unknown", "Chrome", e.name, "REMOVE EXTENSION"]));
  });
  return matrix;
}

function evaluateUSBCompliance() { return [["Endpoint", "Platform", "USB Policy Binding", "Enforcement Vector", "Compliance Posture"], ["Audit Architecture Pending", "N/A", "N/A", "N/A", "UNVERIFIED"]]; }

function evaluateJumpCloudAlerts() {
  let matrix = [["Priority", "Alert", "Resource", "Trigger Event", "Status", "Created"]];
  try {
    let res = UrlFetchApp.fetch(`https://console.jumpcloud.com/api/v2/alerts?limit=100`, { headers: { 'x-api-key': JC_API_KEY }, muteHttpExceptions: true });
    if (res.getResponseCode() === 200) {
      JSON.parse(res.getContentText()).forEach(a => {
        let ctx = a.lastOccurrenceContext || {};
        let trigger = ctx.rule_name || a.description || "System Event";
        let resource = a.sourceName || ctx.name || "Endpoint";
        if (ctx.di_event) { try { let di = JSON.parse(ctx.di_event); if (di.initiated_by) trigger += ` (Actor: ${di.initiated_by.email})`; if (di.system) resource += ` [${di.system.hostname}]`; } catch(e) {} }
        matrix.push([(a.severity || "Low").replace('ALERT_SEVERITY_', '').toTitleCase(), a.title, resource, trigger, (a.status || "Open").replace('ALERT_STATUS_', '').toTitleCase(), (a.createdAt || "").split('T')[0]]);
      });
    }
  } catch(e) {}
  return matrix;
}

function evaluateThreatIntel() {
  let matrix = [["Endpoint", "Threat Category", "Malware Name", "Severity", "Timestamp"]];
  let token = scriptProps.getProperty('TEMP_ESET_TOKEN');
  if(!token) return matrix;
  try {
    let res = UrlFetchApp.fetch(`https://${REGION}.incident-management.eset.systems/v1/detections?pageSize=1000`, {headers: {'Authorization': `Bearer ${token}`}, muteHttpExceptions: true});
    if(res.getResponseCode() === 200) {
      JSON.parse(res.getContentText()).detections.forEach(i => {
        let sev = i.severityLevel.replace('SEVERITY_LEVEL_', '').toTitleCase();
        // Fetching correctly structured hostname from the updated EDR cache
        let hostData = esetDevicesCache[i.context.deviceUuid];
        let host = hostData ? hostData.hostname : "Unknown Identifier";
        matrix.push([host, i.category, i.displayName, sev, i.occurTime.split('T')[0]]);
        if (sev === "Critical" || sev === "High") securityAnomalies.push({ target: host, issue: `EDR Threat Detected: ${i.displayName}` });
      });
    }
  } catch(e) {}
  return matrix;
}

function evaluateSoftwareWatchlist() {
  let matrix = [["Endpoint", "Unauthorized Binary", "Risk Tier"]];
  ['TIER_1', 'TIER_2', 'TIER_3'].forEach(tier => {
    WATCHLIST[tier].forEach(app => {
      let res = UrlFetchApp.fetch(`https://console.jumpcloud.com/api/v2/systeminsights/programs?filter=name:($sw:${encodeURIComponent(app)})`, { headers: { 'x-api-key': JC_API_KEY }, muteHttpExceptions: true });
      if (res.getResponseCode() === 200) JSON.parse(res.getContentText()).forEach(f => matrix.push([systemMap[f.system_id] || "Unknown Identifier", f.name, tier]));
    });
  });
  return matrix;
}

// === 7. THE NUCLEAR TAB ENGINE ===
function getCleanSheet(ss, sheetName) {
  let oldSheet = ss.getSheetByName(sheetName);
  let newSheet;
  if (oldSheet) {
    let index = oldSheet.getIndex();
    newSheet = ss.insertSheet(sheetName + "_TEMP", index - 1);
    ss.deleteSheet(oldSheet);
    newSheet.setName(sheetName);
  } else {
    newSheet = ss.insertSheet(sheetName);
  }
  return newSheet;
}

function buildUniversalHeader(sheet, titleText, descEN, descFR, totalCols) {
  let headerCols = Math.max(totalCols, 5);
  sheet.showColumns(1, sheet.getMaxColumns());
  sheet.insertRowsBefore(1, 5);
  
  sheet.getRange(1, 1, 2, 2).merge().setFormula(`=IMAGE("${URL_LOGO}", 1)`).setBackground(BRAND_SECONDARY);
  sheet.getRange(1, 3, 2, headerCols - 2).merge().setValue(`ENTERPRISE COMMAND CENTER - ${titleText.toUpperCase()}`)
       .setBackground(BRAND_SECONDARY).setFontColor("#FFFFFF").setFontSize(14).setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
       
  sheet.getRange(3, 1, 1, headerCols).merge().setValue(`EN: ${descEN}`).setBackground(BRAND_TERTIARY).setFontColor("#CCCCCC").setFontStyle("italic").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.getRange(4, 1, 1, headerCols).merge().setValue(`FR: ${descFR}`).setBackground(BRAND_TERTIARY).setFontColor("#CCCCCC").setFontStyle("italic").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.getRange(5, 1, 1, headerCols).setBackground("#FFFFFF");
  sheet.getRange(1, 1, 2, headerCols).setBorder(true, true, true, true, false, false, BRAND_PRIMARY, SpreadsheetApp.BorderStyle.SOLID_THICK);
}

function buildTab(ss, sheetName, matrix, formatFn, descEN, descFR) {
  let sheet = getCleanSheet(ss, sheetName);
  let data = (!matrix || matrix.length === 0) ? [["Data", "Status"], ["N/A", "No actionable data found"]] : matrix;
  let totalCols = data[0].length;

  let dataRange = sheet.getRange(6, 1, data.length, totalCols);
  dataRange.setValues(data).setBackground(BRAND_SECONDARY).setFontColor("#FFFFFF").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.getRange(6, 1, 1, totalCols).setBackground(BRAND_PRIMARY).setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
        
  if (formatFn) formatFn(sheet);
  buildUniversalHeader(sheet, sheetName, descEN, descFR, totalCols);
  sheet.setFrozenRows(6);
  sheet.autoResizeColumns(1, totalCols);

  for (let i = 1; i <= totalCols; i++) { sheet.setColumnWidth(i, sheet.getColumnWidth(i) + 30); }
  let maxCols = sheet.getMaxColumns();
  let targetCols = Math.max(totalCols, 5); 
  if (maxCols > targetCols) sheet.deleteColumns(targetCols + 1, maxCols - targetCols);
  
  SpreadsheetApp.flush();
}

function buildGeoMapTab(ss, sheetName, matrix, descEN, descFR) {
  let sheet = getCleanSheet(ss, sheetName);
  
  sheet.getRange(1, 1, sheet.getMaxRows(), sheet.getMaxColumns()).setBackground("#222222"); 
  sheet.setHiddenGridlines(true);
  
  if (!matrix || matrix.length < 2) return;
  sheet.getRange(6, 27, matrix.length, 2).setValues(matrix);
  
  let chart = sheet.newChart().setChartType(Charts.ChartType.GEO).addRange(sheet.getRange(6, 27, matrix.length, 2))
    .setOption('backgroundColor', '#222222').setOption('datalessRegionColor', '#333333').setOption('defaultColor', '#555555')
    .setOption('legend', {textStyle: {color: '#FFFFFF'}}).setOption('colorAxis', {colors: ['#D32F2F', '#FFB300', '#388E3C']})
    .setPosition(7, 2, 0, 0).build();
  sheet.insertChart(chart.modify().setOption('width', 1000).setOption('height', 600).build());
  
  buildUniversalHeader(sheet, "Global Heatmap", descEN, descFR, 25);
  let maxCols = sheet.getMaxColumns();
  if (maxCols > 45) sheet.deleteColumns(46, maxCols - 45);
  
  SpreadsheetApp.flush();
}

// === 8. FORMATTING RULES ===
function buildFleetFormatting(s) {
  s.setConditionalFormatRules([
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("Windows").setBackground("#005A9E").setFontColor("#FFFFFF").setRanges([s.getRange("D7:D1000")]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("macOS").setBackground("#444444").setFontColor("#FFFFFF").setRanges([s.getRange("D7:D1000")]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("Linux").setBackground(BRAND_PRIMARY).setFontColor("#FFFFFF").setRanges([s.getRange("D7:D1000")]).build()
  ]);
}

function buildDirectoryFormatting(s) {
  s.setConditionalFormatRules([
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("ADMIN MISSING MFA").setBackground("#D32F2F").setFontColor("#FFFFFF").setRanges([s.getRange("A7:H1000")]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("SUSPENDED").setBackground("#990000").setFontColor("#FFFFFF").setRanges([s.getRange("A7:H1000")]).build()
  ]);
}

function buildEndpointFormatting(s) {
  s.setConditionalFormatRules([
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("VULNERABLE").setBackground("#D32F2F").setFontColor("#FFFFFF").setRanges([s.getRange("G7:G1000")]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("OUTDATED").setBackground("#FF5722").setFontColor("#FFFFFF").setRanges([s.getRange("G7:G1000")]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("INACTIVE").setBackground("#FFB300").setFontColor("#000000").setRanges([s.getRange("G7:G1000")]).build()
  ]);
}

function buildUSBFormatting(s) { s.setConditionalFormatRules([SpreadsheetApp.newConditionalFormatRule().whenTextContains("UNVERIFIED").setBackground("#FFB300").setFontColor("#000000").setRanges([s.getRange("E7:E1000")]).build()]); }

function buildAlertsFormatting(s) {
  s.setConditionalFormatRules([
    SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("High").setBackground("#D32F2F").setFontColor("#FFFFFF").setRanges([s.getRange("A7:A1000")]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("Medium").setBackground("#FFB300").setFontColor("#000000").setRanges([s.getRange("A7:A1000")]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("Open").setFontColor("#D32F2F").setBold(true).setRanges([s.getRange("E7:E1000")]).build()
  ]);
}

function buildThreatFormatting(s) { s.setConditionalFormatRules([SpreadsheetApp.newConditionalFormatRule().whenTextEqualTo("Critical").setBackground("#D32F2F").setFontColor("#FFFFFF").setRanges([s.getRange("D7:D1000")]).build()]); }
function buildWatchlistFormatting(s) { s.setConditionalFormatRules([SpreadsheetApp.newConditionalFormatRule().whenTextContains("TIER_1").setBackground("#D32F2F").setFontColor("#FFFFFF").setRanges([s.getRange("C7:C1000")]).build()]); }
function buildESETCoverageFormatting(s) {
  s.setConditionalFormatRules([
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("INSTALL EDR").setBackground("#D32F2F").setFontColor("#FFFFFF").setRanges([s.getRange("E7:D1000")]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenTextContains("REMOVE EDR").setBackground("#FFB300").setFontColor("#000000").setRanges([s.getRange("E7:D1000")]).build()
  ]);
}
function buildActionFormatting(s) { s.setConditionalFormatRules([SpreadsheetApp.newConditionalFormatRule().whenCellNotEmpty().setBackground("#D32F2F").setFontColor("#FFFFFF").setRanges([s.getRange("A7:Z1000")]).build()]); }
function buildPasswordFormatting(s) {
  s.setConditionalFormatRules([
    SpreadsheetApp.newConditionalFormatRule().whenNumberBetween(0, 3).setBackground("#D32F2F").setFontColor("#FFFFFF").setRanges([s.getRange("D7:D1000")]).build(),
    SpreadsheetApp.newConditionalFormatRule().whenNumberBetween(4, 14).setBackground("#FFB300").setFontColor("#000000").setRanges([s.getRange("D7:D1000")]).build()
  ]);
}

// === 9. EXECUTIVE SUMMARY DASHBOARD ===
function buildExecutiveSummary(ss, mfaCount, fdeCount, inactiveCount, pwCount, osCount, rebootCount, shadowCount, extCount, chromeCount) {
  let sheet = getCleanSheet(ss, "Executive Summary");
  
  sheet.setHiddenGridlines(true);
  sheet.getRange("A1:AZ100").setBackground("#FFFFFF");
  
  buildUniversalHeader(sheet, "Executive Summary", "High-level overview of global security posture.", "Aperçu de haut niveau de la posture de sécurité.", 13);
  sheet.getRange("D6:N6").merge().setValue(`Security Posture Verified: ${new Date().toISOString().split('T')[0]}`).setFontColor(BRAND_PRIMARY).setFontWeight("bold").setFontSize(12);

  const totalUsers = osCountsSummary.macOS + osCountsSummary.Windows + osCountsSummary.Linux; 
  const totalDevices = Object.keys(systemMap).length;
  const totalESET = Object.keys(esetDevicesCache).length;
  const threatCount = (ss.getSheetByName("Threat Intel")?.createTextFinder("Critical").findAll().length) || 0;
  const watchCount = Math.max(0, (ss.getSheetByName("Software Watchlist")?.getLastRow() || 6) - 6); 
  const alertCount = (ss.getSheetByName("System Alerts")?.createTextFinder("Open").findAll().length) || 0;

  function drawKpi(r, c, title, val) {
    sheet.getRange(r, c, 5, 3).setBackground(BRAND_SECONDARY).setBorder(true, true, true, true, false, false, "#444", SpreadsheetApp.BorderStyle.SOLID_THICK);
    sheet.getRange(r, c, 1, 3).merge().setValue(title).setFontColor("#aaa").setHorizontalAlignment("center").setVerticalAlignment("middle");
    let isAlertState = (val > 0 && !title.includes("Total"));
    sheet.getRange(r+1, c, 4, 3).merge().setValue(val).setFontSize(40).setFontWeight("bold").setFontColor(isAlertState ? "#D32F2F" : BRAND_PRIMARY).setHorizontalAlignment("center").setVerticalAlignment("middle");
  }

  drawKpi(8, 4, "Total Managed Identities", jcUsersCache.length > 0 ? jcUsersCache.length : totalUsers); 
  drawKpi(8, 8, "Total Managed Endpoints", totalDevices);
  drawKpi(8, 12, "Vulnerable Browsers (Chrome)", chromeCount); 
  
  drawKpi(14, 4, "Total EDR Deployments", totalESET); 
  drawKpi(14, 8, "Privileged Identities Missing MFA", mfaCount); 
  drawKpi(14, 12, "Critical EDR Detections", threatCount);
  
  drawKpi(20, 4, "Unencrypted Storage Volumes", fdeCount); 
  drawKpi(20, 8, "Outdated OS Baselines", osCount); 
  drawKpi(20, 12, "Inactive Endpoints (>90 Days)", inactiveCount);
  
  drawKpi(26, 4, "Open Native Alerts", alertCount); 
  drawKpi(26, 8, "Identities Nearing Password Expiry", pwCount);
  drawKpi(26, 12, "Endpoints Requiring Reboot", rebootCount);
  
  drawKpi(32, 4, "Malicious Extensions Identified", extCount); 
  drawKpi(32, 8, "Shadow Administrator Accounts", shadowCount); 
  drawKpi(32, 12, "Unsanctioned Software Deployments", watchCount);

  let maxCols = sheet.getMaxColumns();
  if (maxCols > 20) sheet.deleteColumns(21, maxCols - 20);
  
  SpreadsheetApp.flush();
}

// === 10. PIPELINES ===
function pushToBigQueryCSV(data, table) {
  if (!data || data.length < 2) return;
  const csv = data.map(r => r.map(v => `"${String(v).replace(/"/g, '""').replace(/\n/g, ' ')}"`).join(",")).join("\n");
  const blob = Utilities.newBlob(csv, 'application/octet-stream');
  try { BigQuery.Jobs.insert({ configuration: { load: { destinationTable: { projectId: PROJECT_ID, datasetId: DATASET_ID, tableId: table }, sourceFormat: 'CSV', skipLeadingRows: 1, writeDisposition: 'WRITE_APPEND' } } }, PROJECT_ID, blob); } catch (e) {}
}

function dispatchLiveAgentSOAR(anomalies) {
  anomalies.forEach(a => { UrlFetchApp.fetch("https://your-domain.ladesk.com/api/v3/tickets", { "method": "post", "contentType": "application/json", "headers": { "apikey": LA_API_KEY }, "payload": JSON.stringify({ "subject": `[SECURITY ALARM] ${a.issue} on ${a.target}`, "message": `Target Asset: ${a.target}\nViolation: ${a.issue}`, "departmentid": "your-dept-id" }), "muteHttpExceptions": true }); });
}

function dispatchPipelineFailureAlert(err) { UrlFetchApp.fetch("https://your-domain.ladesk.com/api/v3/tickets", { "method": "post", "contentType": "application/json", "headers": { "apikey": LA_API_KEY }, "payload": JSON.stringify({ "subject": "[CRITICAL] CSPM Pipeline Failure", "message": `Execution Exception:\n${err}`, "departmentid": "your-dept-id" }), "muteHttpExceptions": true }); }
function showSidebar() { SpreadsheetApp.getUi().showSidebar(HtmlService.createHtmlOutputFromFile('Sidebar').setTitle('Active Response').setWidth(300)); }
String.prototype.toTitleCase = function () { return this.replace(/\w\S*/g, function(txt){return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();}); };

```
