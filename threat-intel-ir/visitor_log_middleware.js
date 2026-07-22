/**
 * Enterprise Visitor Log Script
 * Routes visitor form submissions to the Regional Security Operations queue.
 */

function processVisitorLog(e) {
  try {
    // 1. Configuration (Production: Regional Security Queue)
    const targetEmail = "security-ops@your-domain.com"; 
    
    const form = FormApp.getActiveForm();
    const formTitle = form.getTitle();
    
    // Generate a unique tracking ID
    const timestamp = new Date();
    const trackingId = "VIS-" + Math.floor(timestamp.getTime() / 1000).toString().slice(-6);

    // 2. Extract Form Data
    const formResponses = e.response.getItemResponses();
    const submitterEmail = e.response.getRespondentEmail() || "Front Desk Agent";
    
    let tableRowsHtml = "";

    // Loop through the responses to build the email table
    formResponses.forEach(response => {
      let question = response.getItem().getTitle();
      let answer = response.getResponse();
      
      if (Array.isArray(answer)) answer = answer.join(", ");
      
      tableRowsHtml += `
        <tr>
          <td style="padding: 12px; border: 1px solid #d4d4d4; font-weight: bold; width: 40%; background-color: #f4f6f8; color: #333;">${question}</td>
          <td style="padding: 12px; border: 1px solid #d4d4d4; color: #444;">${answer}</td>
        </tr>`;
    });

    // 3. Build HTML Email Payload
    const htmlBody = `
      <div style="font-family: 'Segoe UI', Tahoma, Geneva, sans-serif; max-width: 800px; border: 1px solid #ccc; border-radius: 6px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
        
        <div style="background-color: #ffffff; padding: 15px 20px; border-bottom: 3px solid #ED6B28; text-align: left; border-radius: 6px 6px 0 0;">
          <img src="https://your-enterprise-domain.com/assets/img/logo.png" alt="Enterprise Security" style="height: 40px; display: block;">
        </div>

        <div style="background-color: #ED6B28; color: white; padding: 15px 20px;">
          <h2 style="margin: 0; font-size: 20px;">Visitor Log: ${formTitle}</h2>
          <p style="margin: 5px 0 0 0; font-size: 13px; opacity: 0.9;">Log ID: ${trackingId}</p>
        </div>

        <div style="padding: 15px 20px; background-color: #e9ecef; border-bottom: 1px solid #ccc;">
          <p style="margin: 3px 0; font-size: 14px;"><strong>Registered By:</strong> ${submitterEmail}</p>
          <p style="margin: 3px 0; font-size: 14px;"><strong>Timestamp:</strong> ${timestamp.toUTCString()}</p>
        </div>

        <div style="padding: 20px;">
          <table style="width: 100%; border-collapse: collapse; font-size: 14px; text-align: left;">
            <tbody>
              ${tableRowsHtml}
            </tbody>
          </table>
        </div>
        
      </div>
    `;

    // 4. Send Email
    MailApp.sendEmail({
      to: targetEmail,
      subject: `[Visitor Log] ${trackingId} - New Registration`,
      htmlBody: htmlBody,
      replyTo: submitterEmail
    });

  } catch (error) {
    Logger.log("Error: " + error.toString());
  }
}