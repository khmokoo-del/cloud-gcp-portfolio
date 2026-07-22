/**
 * Enterprise Security Routing Middleware
 * Target: Security Operations Center (SIEM/Ticketing Integration)
 */

function processSecurityRequest(e) {
  try {
    // 1. CONFIGURATION (Set to SOC queue for production)
    const targetEmail = "soc-escalations@your-domain.com"; 
    
    const form = FormApp.getActiveForm();
    const formTitle = form.getTitle();
    
    // Generate an Enterprise Tracking ID
    const timestamp = new Date();
    const trackingId = "SEC-INC-" + Math.floor(timestamp.getTime() / 1000).toString().slice(-6);

    // 2. EXTRACT SUBMISSION DATA
    const formResponses = e.response.getItemResponses();
    const submitterEmail = e.response.getRespondentEmail() || "Authenticated User";
    
    let rawDataObj = {}; 
    let tableRowsHtml = "";

    // Dynamically loop through the global questions
    formResponses.forEach(response => {
      let question = response.getItem().getTitle();
      let answer = response.getResponse();
      
      if (Array.isArray(answer)) answer = answer.join(", ");
      
      rawDataObj[question] = answer;
      
      tableRowsHtml += `
        <tr>
          <td style="padding: 12px; border: 1px solid #d4d4d4; font-weight: bold; width: 35%; background-color: #f4f6f8; color: #333;">${question}</td>
          <td style="padding: 12px; border: 1px solid #d4d4d4; color: #444;">${answer}</td>
        </tr>`;
    });

    // 3. CONSTRUCT EXECUTIVE HTML PAYLOAD (Enterprise Branded)
    const htmlBody = `
      <div style="font-family: 'Segoe UI', Tahoma, Geneva, sans-serif; max-width: 800px; border: 1px solid #ccc; border-radius: 6px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
        
        <div style="background-color: #ffffff; padding: 15px 20px; border-bottom: 3px solid #ED6B28; text-align: left; border-radius: 6px 6px 0 0;">
          <img src="https://your-enterprise-domain.com/assets/img/logo.png" alt="Enterprise Security" style="height: 40px; display: block;">
        </div>

        <div style="background-color: #ED6B28; color: white; padding: 15px 20px;">
          <h2 style="margin: 0; font-size: 20px;">Global Security Escalation: ${formTitle}</h2>
          <p style="margin: 5px 0 0 0; font-size: 13px; opacity: 0.9;">System ID: ${trackingId}</p>
        </div>

        <div style="padding: 15px 20px; background-color: #e9ecef; border-bottom: 1px solid #ccc;">
          <p style="margin: 3px 0; font-size: 14px;"><strong>Authorized Submitter:</strong> ${submitterEmail}</p>
          <p style="margin: 3px 0; font-size: 14px;"><strong>UTC Timestamp:</strong> ${timestamp.toUTCString()}</p>
        </div>

        <div style="padding: 20px;">
          <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
            <tbody>
              ${tableRowsHtml}
            </tbody>
          </table>
        </div>

        <div style="background-color: #2b2b2b; padding: 15px 20px; border-radius: 0 0 6px 6px; font-family: monospace; font-size: 12px; color: #a9b7c6;">
          <p style="margin-top: 0; color: #ED6B28;"><strong>RAW SYSTEM PAYLOAD // SIEM INGESTION:</strong></p>
          <pre style="white-space: pre-wrap; margin: 0;">${JSON.stringify(rawDataObj, null, 2)}</pre>
        </div>
        
      </div>
    `;

    // 4. TRANSMIT TO SOC TICKETING SYSTEM
    MailApp.sendEmail({
      to: targetEmail,
      subject: `[SEC-INC Alert] ${trackingId} - New Escalation`,
      htmlBody: htmlBody,
      replyTo: submitterEmail
    });

  } catch (error) {
    Logger.log("Middleware Failure: " + error.toString());
  }
}