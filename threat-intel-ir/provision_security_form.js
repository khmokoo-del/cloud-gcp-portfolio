/**
 * Enterprise Security: Automated Form Provisioning Script
 * Module: Global Security & Compliance Escalation Portal (Bilingual)
 * Target Environment: Production / SOC Ticketing Integration
 */

function provisionSecurityEscalationForm() {
  // Initialize form object and apply metadata
  const form = FormApp.create('[SEC-INC] Global Security Escalation / Escalade de Sécurité Globale');
  
  form.setDescription('CONFIDENTIAL: This portal is strictly for the escalation of physical security incursions, compliance failures, and biometric/infrastructure incidents.\n\nCONFIDENTIEL : Ce portail est strictement réservé au signalement des failles de sécurité physique, des non-conformités et des incidents liés à l\'infrastructure biométrique.\n\n(ISO 27001 / MFA Protocols)');
  form.setCollectEmail(true); 
  form.setProgressBar(true);

  // Define Array: Geographic Operational Nodes
  form.addListItem()
      .setTitle('Facility / Installation (Jurisdiction)')
      .setChoiceValues([
        'EMEA - London, UK', 
        'EMEA - Paris, France', 
        'EMEA - Berlin, Germany', 
        'NA - New York, USA', 
        'NA - Toronto, Canada', 
        'APAC - Tokyo, Japan', 
        'APAC - Sydney, Australia', 
        'APAC - Singapore', 
        'LATAM - Sao Paulo, Brazil', 
        'LATAM - Mexico City, Mexico', 
        'Global / HQ (Siège)'
      ])
      .setRequired(true);

  // Construct Checkbox Array: Incident Classification Schema
  form.addMultipleChoiceItem()
      .setTitle('Incident Classification / Classification de l\'Incident')
      .setChoiceValues([
        'Physical Incursion / Intrusion Physique & Accès Non Autorisé',
        'Access Control Degradation / Défaillance de la Vidéosurveillance ou du Contrôle d\'Accès',
        'Asset Compromise / Compromission de Matériel Biométrique ou Sécurisé',
        'Occupational Threat / Menace pour la Sécurité du Personnel sur Site',
        'Regulatory Non-Conformity / Non-Conformité ou Échec d\'Audit'
      ])
      .setRequired(true);

  // Construct Checkbox Array: Risk Matrix & Escalation Tiers
  form.addMultipleChoiceItem()
      .setTitle('Risk Tier / Niveau de Risque (MFA Escalation)')
      .setHelpText('Assess the compliance risk. / Évaluez le risque de conformité.')
      .setChoiceValues([
        'Tier 1 - Critical / Critique (Immediate Executive Escalation Required / Escalade Immédiate)',
        'Tier 2 - Elevated / Élevé (Severe SOP Breach / Violation Majeure des Procédures)',
        'Tier 3 - Routine (Standard Hardware Degradation / Panne Matérielle Standard)'
      ])
      .setRequired(true);

  // Instantiate Text Input: Event Narrative
  form.addParagraphTextItem()
      .setTitle('Incident Synopsis / Synopsis de l\'Incident')
      .setHelpText('Include exact local timestamps and containment actions. / Inclure les heures locales exactes et les mesures de confinement prises.')
      .setRequired(true);

  // Instantiate Text Input: Telemetry & Forensics
  form.addParagraphTextItem()
      .setTitle('Evidentiary Artifacts / Preuves et Artefacts')
      .setHelpText('Links to CCTV, access logs, or police reports. / Liens vers la vidéosurveillance, les journaux d\'accès ou les rapports de police.')
      .setRequired(false);

  // Output execution status to the stack trace
  Logger.log('Provisioning executed successfully. Form instance initialized.');
  Logger.log('Admin Edit URI: ' + form.getEditUrl());
}