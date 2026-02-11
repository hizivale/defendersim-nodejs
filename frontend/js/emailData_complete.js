/**
 * DefenderSim Email Dataset - 60 Complete Multilingual Phishing Examples
 * 
 * Each email includes:
 * - Complete email body content
 * - Full authentication results (DMARC, SPF, DKIM)
 * - All 6 framework analyses with scores, patterns, and evidence
 * - Detailed Ollama LLM analysis with summary, reasoning, and recommendations
 * 
 * Classifications:
 * - TP (True Positive): Phishing correctly identified as phishing (45 emails)
 * - TN (True Negative): Legitimate correctly identified as safe (9 emails)
 * - FP (False Positive): Legitimate wrongly flagged as phishing (4 emails)
 * - FN (False Negative): Phishing that slipped through (2 emails)
 * 
 * Languages: German (24), English (24), French (12)
 * Risk Levels: HIGH (38), MEDIUM (14), LOW (8)
 * 
 * Performance Metrics:
 * - Accuracy: 93.3% (56/60 correct)
 * - Precision: 91.8% (45/49 true positives)
 * - Recall: 95.7% (45/47 phishing detected)
 * - F1 Score: 93.7%
 */

const emailData = [
    // ==================== GERMAN EMAILS (24 total) ====================
    
    // Email 1 - German HIGH TP - Deutsche Bank Phishing
    {
        id: 1,
        subject: "DRINGEND: Ihr Konto wurde gesperrt",
        from: "sicherheit@deutsche-bank-verify.tk",
        language: "de",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Sehr geehrter Kunde,

Wir haben verdächtige Aktivitäten auf Ihrem Konto festgestellt. Aus Sicherheitsgründen wurde Ihr Konto vorsorglich gesperrt.

Um Ihr Konto wieder freizuschalten, müssen Sie Ihre Identität bestätigen.

Bitte klicken Sie hier: http://deutsche-bank-verify.tk/login?session=x7f9k2m

WICHTIG: Sie haben nur 24 Stunden Zeit, um diese Bestätigung durchzuführen. Andernfalls wird Ihr Konto dauerhaft geschlossen und alle Transaktionen werden blockiert.

Bei Fragen wenden Sie sich bitte an unseren Kundendienst.

Mit freundlichen Grüßen,
Deutsche Bank Sicherheitsteam

Diese E-Mail wurde automatisch generiert. Bitte antworten Sie nicht auf diese Nachricht.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 95,
                patterns: [
                    "Urgency keyword: DRINGEND",
                    "Urgency keyword: gesperrt",
                    "Urgency keyword: 24 Stunden",
                    "Suspicious URL detected",
                    "Credential request detected"
                ],
                evidence: [
                    "Found 'DRINGEND' in subject line",
                    "Account suspension threat",
                    "Suspicious domain .tk TLD",
                    "24-hour deadline creates pressure",
                    "Direct link to credential page"
                ]
            },
            owasp: {
                score: 88,
                patterns: [
                    "Malicious redirect detected",
                    "Suspicious URL parameters",
                    "Non-HTTPS link for sensitive operation"
                ],
                evidence: [
                    "URL uses .tk domain (common in phishing)",
                    "Session parameter suggests data collection",
                    "HTTP instead of HTTPS for banking"
                ]
            },
            nist: {
                score: 92,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Sender domain does not match Deutsche Bank",
                    "deutsche-bank-verify.tk is not official domain"
                ]
            },
            iso27001: {
                score: 90,
                patterns: [
                    "Sensitive data request via email",
                    "Unencrypted link for credentials",
                    "Security policy violation"
                ],
                evidence: [
                    "Requests identity confirmation via email link",
                    "HTTP link for sensitive banking operation",
                    "Violates standard banking security practices"
                ]
            },
            nessus: {
                score: 87,
                patterns: [
                    "Known phishing domain pattern",
                    "Malware signature detected"
                ],
                evidence: [
                    "Domain matches known phishing campaigns",
                    ".tk TLD commonly used in attacks"
                ]
            },
            openvas: {
                score: 89,
                patterns: [
                    "Zero-day threat indicators",
                    "Social engineering tactics"
                ],
                evidence: [
                    "Combination of urgency and credential request",
                    "Fear-based manipulation (account closure)"
                ]
            }
        },
        ollama: {
            summary: "This is a high-confidence phishing email impersonating Deutsche Bank. The email uses multiple urgency tactics and threatens permanent account closure to pressure the recipient into clicking a malicious link and providing their banking credentials.",
            reasoning: "Critical red flags detected across all frameworks: (1) Complete authentication failure - DMARC, SPF, and DKIM all failed, indicating sender spoofing. (2) Suspicious domain - deutsche-bank-verify.tk is not an official Deutsche Bank domain; the .tk TLD is commonly used in phishing. (3) Urgency tactics - 24-hour deadline creates pressure for hasty action. (4) Security violations - requests credentials via unencrypted HTTP link, which legitimate banks never do. (5) All 6 frameworks scored above 85%, indicating unanimous high-risk assessment.",
            recommendations: [
                "Delete this email immediately without clicking any links",
                "Report to IT security team and email provider as phishing attempt",
                "Do not provide any personal or banking information",
                "Verify account status by logging into Deutsche Bank through official website or mobile app only",
                "Contact Deutsche Bank customer service through official phone number if you have concerns",
                "Enable two-factor authentication on your account if not already active",
                "Monitor your account for any unauthorized transactions"
            ]
        }
    },

    // Email 2 - German LOW TN - Legitimate Amazon Order
    {
        id: 2,
        subject: "Ihre Bestellung bei Amazon.de",
        from: "rechnung@amazon.de",
        language: "de",
        riskLevel: "LOW",
        classification: "TN",
        body: `Guten Tag,

Vielen Dank für Ihre Bestellung bei Amazon.de.

Bestelldetails:
Bestellnummer: 302-1234567-8901234
Bestelldatum: 10. Februar 2026
Gesamtbetrag: 49,99 EUR

Bestellte Artikel:
1. Buch: "Cybersecurity Fundamentals" (2. Auflage)
   Menge: 1
   Preis: 49,99 EUR

Lieferadresse:
Max Mustermann
Musterstraße 123
12345 Berlin
Deutschland

Zahlungsmethode: Kreditkarte ****1234

Voraussichtliche Lieferung: 12. Februar 2026

Sie können den Status Ihrer Bestellung jederzeit in Ihrem Amazon-Konto unter "Meine Bestellungen" einsehen.

Vielen Dank, dass Sie bei Amazon einkaufen!

Mit freundlichen Grüßen,
Ihr Amazon.de Team

Diese E-Mail wurde automatisch generiert.`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 15,
                patterns: [],
                evidence: [
                    "No urgency keywords detected",
                    "Legitimate order confirmation format",
                    "Professional language and structure",
                    "No suspicious links or requests"
                ]
            },
            owasp: {
                score: 10,
                patterns: [],
                evidence: [
                    "No suspicious URLs detected",
                    "No script injection attempts",
                    "Standard email format"
                ]
            },
            nist: {
                score: 8,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain matches Amazon.de"
                ]
            },
            iso27001: {
                score: 12,
                patterns: [],
                evidence: [
                    "No sensitive data requests",
                    "Standard business communication",
                    "Appropriate use of masked payment info"
                ]
            },
            nessus: {
                score: 10,
                patterns: [],
                evidence: [
                    "No malware signatures detected",
                    "No exploit attempts found"
                ]
            },
            openvas: {
                score: 11,
                patterns: [],
                evidence: [
                    "No vulnerability indicators",
                    "Standard legitimate email structure"
                ]
            }
        },
        ollama: {
            summary: "This appears to be a legitimate order confirmation email from Amazon.de. All authentication checks passed successfully and no phishing indicators were detected by any framework.",
            reasoning: "All security indicators point to legitimacy: (1) Perfect authentication - DMARC, SPF, and DKIM all passed, confirming the email genuinely came from Amazon.de servers. (2) Standard format - matches typical Amazon order confirmation structure with specific order details, delivery information, and masked payment data. (3) No suspicious elements - no urgency tactics, no credential requests, no suspicious links. (4) Low framework scores across all 6 frameworks (8-15%) indicate very low risk. (5) Professional language and appropriate business communication style.",
            recommendations: [
                "Safe to read and keep for your records",
                "Verify order details match your actual purchase in your Amazon account",
                "If you did not place this order, contact Amazon customer service immediately through official channels",
                "Save this email for tracking and potential returns",
                "No immediate security action required"
            ]
        }
    },

    // Email 3 - German HIGH TP - Sparkasse Phishing
    {
        id: 3,
        subject: "Sparkasse: Sicherheitswarnung - Sofortige Handlung erforderlich",
        from: "info@sparkasse-sicherheit.com",
        language: "de",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Wichtige Sicherheitsmitteilung

Sehr geehrter Sparkassen-Kunde,

Wir haben einen unbefugten Zugriff auf Ihr Online-Banking-Konto festgestellt. Aus Sicherheitsgründen wurden Ihre Zugangsdaten vorsorglich gesperrt.

SOFORTIGE HANDLUNG ERFORDERLICH:

Um Ihr Konto zu schützen und wieder freizuschalten, müssen Sie Ihre Zugangsdaten JETZT aktualisieren.

Klicken Sie hier zur Aktualisierung: http://sparkasse-verify.com/update?token=x7f9k2m&user=verify

WICHTIG: Bei Nichtbeachtung wird Ihr Konto innerhalb von 48 Stunden dauerhaft gesperrt und alle Transaktionen werden blockiert.

Betroffene Dienste:
- Online-Banking
- Mobile Banking App
- Kreditkartentransaktionen

Bitte führen Sie die Aktualisierung umgehend durch, um Unterbrechungen zu vermeiden.

Mit freundlichen Grüßen,
Ihr Sparkassen-Sicherheitsteam

Diese E-Mail wurde automatisch vom Sicherheitssystem generiert.
Sparkasse Finanzgruppe - Sicher und vertrauenswürdig seit 1778`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "unknown"
        },
        frameworks: {
            mlClassifier: {
                score: 92,
                patterns: [
                    "Urgency keyword: SOFORTIGE",
                    "Urgency keyword: JETZT",
                    "Urgency keyword: gesperrt",
                    "Urgency keyword: 48 Stunden",
                    "Suspicious URL detected",
                    "Credential update request"
                ],
                evidence: [
                    "Multiple urgency indicators in caps",
                    "48-hour deadline threat",
                    "Suspicious domain sparkasse-verify.com",
                    "Direct credential update request",
                    "Fear-based language about account blocking"
                ]
            },
            owasp: {
                score: 85,
                patterns: [
                    "Malicious redirect detected",
                    "Suspicious URL parameters",
                    "Data collection attempt"
                ],
                evidence: [
                    "Non-Sparkasse domain with query parameters",
                    "URL encoding suggests credential harvesting",
                    "HTTP instead of HTTPS for banking"
                ]
            },
            nist: {
                score: 90,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM status unknown",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "Sender domain 'sparkasse-sicherheit.com' does not match official Sparkasse domains",
                    "Authentication failures indicate spoofing",
                    "Official Sparkasse uses sparkasse.de domain"
                ]
            },
            iso27001: {
                score: 88,
                patterns: [
                    "Sensitive data request via email",
                    "Security policy violation",
                    "Unencrypted credential request"
                ],
                evidence: [
                    "Requests credential update via email link",
                    "Violates banking security best practices",
                    "Legitimate banks never request credentials via email"
                ]
            },
            nessus: {
                score: 86,
                patterns: [
                    "Known phishing pattern",
                    "Domain matches threat database"
                ],
                evidence: [
                    "Domain matches known Sparkasse phishing campaigns",
                    "Similar patterns seen in previous attacks"
                ]
            },
            openvas: {
                score: 87,
                patterns: [
                    "Social engineering tactics",
                    "Exploit attempt in URL structure"
                ],
                evidence: [
                    "Combination of fear, urgency, and authority",
                    "Suspicious URL structure with token parameter",
                    "Attempts to bypass user caution with deadline"
                ]
            }
        },
        ollama: {
            summary: "This is a classic phishing attack impersonating Sparkasse bank. The email employs sophisticated social engineering tactics including fear, urgency, and authority to trick users into providing their banking credentials on a fraudulent website.",
            reasoning: "Multiple critical indicators confirm this is phishing: (1) Authentication failures - DMARC and SPF failed, DKIM unknown, indicating sender spoofing. (2) Domain spoofing - sparkasse-sicherheit.com is NOT an official Sparkasse domain (official is sparkasse.de). (3) Extreme urgency - uses caps lock, multiple urgency keywords, and 48-hour deadline to pressure hasty action. (4) Security violations - requests credential updates via email link, which legitimate banks never do. (5) Suspicious URL - contains parameters suggesting data harvesting. (6) All frameworks scored 85%+ indicating unanimous high-risk assessment. The email even includes fake credibility markers like 'seit 1778' to appear legitimate.",
            recommendations: [
                "Delete this email immediately without clicking any links",
                "Report as phishing to your email provider and Sparkasse",
                "Never click links in unsolicited banking emails",
                "Contact Sparkasse directly through their official website (sparkasse.de) or phone number if you have concerns about your account",
                "Verify account status by logging into online banking through official channels only",
                "Monitor your account for any unauthorized activity",
                "Enable two-factor authentication if not already active",
                "Educate family members about similar phishing attempts"
            ]
        }
    }
];

    // Email 4 - German MEDIUM TP - DHL Delivery Scam
    {
        id: 4,
        subject: "DHL Paketbenachrichtigung - Zustellung fehlgeschlagen",
        from: "service@dhl-paket-info.com",
        language: "de",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Guten Tag,

Leider konnten wir Ihr Paket heute nicht zustellen.

Sendungsnummer: DHL7849302847
Zustellversuch: 10. Februar 2026, 14:32 Uhr
Grund: Empfänger nicht angetroffen

Um Ihr Paket zu erhalten, müssen Sie eine neue Zustellung vereinbaren.

Bitte klicken Sie hier: http://dhl-paket-info.com/redelivery?id=7849302847

Hinweis: Für die erneute Zustellung fällt eine Bearbeitungsgebühr von 2,99 EUR an. Bitte zahlen Sie diese online, um die Zustellung zu veranlassen.

Ihr Paket wird 7 Tage in der Filiale aufbewahrt. Danach erfolgt die Rücksendung an den Absender.

Mit freundlichen Grüßen,
DHL Paket Service

DHL - Ein Unternehmen der Deutschen Post`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 68,
                patterns: [
                    "Suspicious URL detected",
                    "Payment request detected",
                    "Time pressure (7 days)",
                    "Grammar acceptable but domain suspicious"
                ],
                evidence: [
                    "Domain dhl-paket-info.com is not official DHL",
                    "Requests payment for redelivery (unusual)",
                    "Creates urgency with 7-day deadline",
                    "Small fee request (common phishing tactic)"
                ]
            },
            owasp: {
                score: 62,
                patterns: [
                    "Suspicious URL structure",
                    "Payment collection attempt"
                ],
                evidence: [
                    "Non-DHL domain with tracking-like parameters",
                    "Redirects to payment page",
                    "HTTP instead of HTTPS for payment"
                ]
            },
            nist: {
                score: 75,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain mismatch"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official DHL uses dhl.de domain",
                    "Sender spoofing detected"
                ]
            },
            iso27001: {
                score: 65,
                patterns: [
                    "Payment request via email link",
                    "Unencrypted payment page"
                ],
                evidence: [
                    "Requests payment through email link",
                    "HTTP link for financial transaction",
                    "Violates payment security standards"
                ]
            },
            nessus: {
                score: 60,
                patterns: [
                    "Delivery scam pattern detected"
                ],
                evidence: [
                    "Matches known delivery phishing campaigns",
                    "Small fee request is common tactic"
                ]
            },
            openvas: {
                score: 63,
                patterns: [
                    "Social engineering (missed delivery)",
                    "Financial fraud attempt"
                ],
                evidence: [
                    "Exploits expectation of package delivery",
                    "Small payment amount reduces suspicion",
                    "Time pressure with 7-day deadline"
                ]
            }
        },
        ollama: {
            summary: "This is a medium-risk phishing email impersonating DHL. It uses a fake missed delivery notification to trick recipients into paying a small fee, likely leading to credit card theft or further scams.",
            reasoning: "Several indicators suggest phishing: (1) Authentication failures - all checks failed, indicating sender spoofing. (2) Domain mismatch - dhl-paket-info.com is not official DHL (should be dhl.de). (3) Unusual payment request - legitimate DHL rarely charges redelivery fees, and never via email link. (4) Small fee tactic - 2.99 EUR is designed to seem insignificant while harvesting payment data. (5) Framework scores in 60-75% range indicate medium risk. The email is well-written and plausible, making it more dangerous than obvious scams.",
            recommendations: [
                "Do not click the link or provide any payment information",
                "Delete this email",
                "If expecting a package, check delivery status directly on dhl.de website or app",
                "Contact DHL customer service through official channels if you have questions",
                "Report to DHL and your email provider as phishing",
                "Be cautious of similar delivery notification scams from other carriers",
                "Never pay unexpected fees through email links"
            ]
        }
    },

    // Email 5 - German HIGH TP - PayPal Account Suspension
    {
        id: 5,
        subject: "Wichtig: Ihr PayPal-Konto wurde eingeschränkt",
        from: "service@paypal-sicherheit.de",
        language: "de",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Sehr geehrter PayPal-Kunde,

Wir haben ungewöhnliche Aktivitäten in Ihrem PayPal-Konto festgestellt.

Zu Ihrer Sicherheit haben wir Ihr Konto vorübergehend eingeschränkt.

Betroffene Funktionen:
• Geld senden und empfangen
• Guthaben abheben
• Online-Zahlungen tätigen
• Käuferschutz nutzen

Um die Einschränkung aufzuheben, müssen Sie Ihre Identität bestätigen und Ihre Kontoinformationen aktualisieren.

Jetzt bestätigen: http://paypal-verify.com/de/resolution?case=PP-004-729-384

WICHTIG: Wenn Sie nicht innerhalb von 72 Stunden reagieren, wird Ihr Konto dauerhaft geschlossen und Ihr Guthaben einbehalten.

Aktuelles Guthaben: 847,32 EUR

Warum ist das passiert?
Wir haben eine Transaktion von einem neuen Gerät festgestellt, das wir nicht erkennen konnten.

Vielen Dank für Ihr Verständnis.

Mit freundlichen Grüßen,
PayPal Kundenservice

Copyright © 1999-2026 PayPal. Alle Rechte vorbehalten.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 94,
                patterns: [
                    "Urgency keyword: Wichtig",
                    "Urgency keyword: eingeschränkt",
                    "Urgency keyword: 72 Stunden",
                    "Urgency keyword: dauerhaft geschlossen",
                    "Suspicious URL detected",
                    "Account balance mentioned (social engineering)"
                ],
                evidence: [
                    "'Wichtig' in subject creates urgency",
                    "Multiple restriction threats",
                    "72-hour deadline pressure",
                    "Mentions specific balance to appear legitimate",
                    "Domain paypal-verify.com is suspicious"
                ]
            },
            owasp: {
                score: 89,
                patterns: [
                    "Malicious redirect detected",
                    "Credential harvesting attempt",
                    "Suspicious case number parameter"
                ],
                evidence: [
                    "Non-PayPal domain with fake case number",
                    "URL designed to collect login credentials",
                    "HTTP instead of HTTPS for financial service"
                ]
            },
            nist: {
                score: 93,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing (paypal-sicherheit.de)"
                ],
                evidence: [
                    "Complete authentication failure",
                    "Official PayPal uses paypal.com or paypal.de",
                    "Sender domain is fraudulent"
                ]
            },
            iso27001: {
                score: 91,
                patterns: [
                    "Sensitive data request via email",
                    "Identity verification through email link",
                    "Security policy violation"
                ],
                evidence: [
                    "Requests identity confirmation via email",
                    "Threatens account closure for non-compliance",
                    "Legitimate PayPal never requests verification via email"
                ]
            },
            nessus: {
                score: 88,
                patterns: [
                    "Known PayPal phishing pattern",
                    "Matches threat signature database"
                ],
                evidence: [
                    "Similar to documented PayPal phishing campaigns",
                    "Account restriction theme is common tactic"
                ]
            },
            openvas: {
                score: 90,
                patterns: [
                    "Financial fraud attempt",
                    "Social engineering (balance mention)",
                    "Authority exploitation (PayPal brand)"
                ],
                evidence: [
                    "Mentions specific balance to create urgency",
                    "Uses PayPal authority to gain trust",
                    "Combines fear (closure) with loss (balance held)"
                ]
            }
        },
        ollama: {
            summary: "This is a high-confidence PayPal phishing email. It uses sophisticated social engineering by mentioning a specific account balance and multiple restriction threats to pressure the recipient into clicking a malicious link and providing their PayPal login credentials.",
            reasoning: "Critical phishing indicators across all frameworks: (1) Complete authentication failure - DMARC, SPF, and DKIM all failed, confirming sender spoofing. (2) Domain spoofing - paypal-sicherheit.de and paypal-verify.com are NOT official PayPal domains (official is paypal.com or paypal.de). (3) Advanced social engineering - mentions specific balance (847,32 EUR) to create urgency and appear legitimate. (4) Multiple threats - account restrictions, permanent closure, balance withholding. (5) 72-hour deadline creates pressure. (6) All 6 frameworks scored 88%+ indicating unanimous high-risk assessment. The professional formatting and copyright notice are designed to appear legitimate.",
            recommendations: [
                "Delete this email immediately without clicking any links",
                "Report to PayPal through their official phishing reporting system",
                "Log into PayPal directly through paypal.com or the official app to check your actual account status",
                "Never click links in unsolicited PayPal emails",
                "PayPal will never ask you to confirm your identity via email",
                "If you clicked the link, change your PayPal password immediately and enable two-factor authentication",
                "Monitor your PayPal account and linked bank accounts for unauthorized transactions",
                "Contact PayPal customer service through official channels if you have concerns"
            ]
        }
    },

    // Email 6 - German LOW TN - Telekom Invoice
    {
        id: 6,
        subject: "Ihre Telekom Rechnung für Februar 2026",
        from: "rechnung@telekom.de",
        language: "de",
        riskLevel: "LOW",
        classification: "TN",
        body: `Guten Tag,

Ihre Rechnung für Februar 2026 ist jetzt verfügbar.

Kundennummer: 123456789
Rechnungsnummer: 202602-987654
Rechnungsdatum: 01. Februar 2026
Fälligkeitsdatum: 15. Februar 2026

Rechnungsbetrag: 39,95 EUR

Ihre Rechnung im Detail:
- MagentaMobil S: 29,95 EUR
- Datenvolumen Zusatzoption: 10,00 EUR

Zahlungsart: SEPA-Lastschrift
Kontoinhaber: Max Mustermann
IBAN: DE89 **** **** **** **34

Der Betrag wird automatisch von Ihrem Konto abgebucht.

Sie können Ihre Rechnung jederzeit im Kundencenter unter www.telekom.de/kundencenter einsehen und herunterladen.

Bei Fragen zu Ihrer Rechnung erreichen Sie uns:
- Telefon: 0800 330 1000 (kostenlos)
- Online: www.telekom.de/hilfe

Mit freundlichen Grüßen,
Ihr Telekom Team

Deutsche Telekom AG
Hauptverwaltung
Friedrich-Ebert-Allee 140
53113 Bonn`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 18,
                patterns: [],
                evidence: [
                    "No urgency keywords",
                    "Standard invoice format",
                    "Professional language",
                    "Legitimate contact information provided",
                    "No suspicious links or requests"
                ]
            },
            owasp: {
                score: 12,
                patterns: [],
                evidence: [
                    "No suspicious URLs",
                    "Official Telekom domain used",
                    "No script injection attempts",
                    "Standard business email"
                ]
            },
            nist: {
                score: 9,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain matches Telekom",
                    "All security checks passed"
                ]
            },
            iso27001: {
                score: 14,
                patterns: [],
                evidence: [
                    "No sensitive data requests",
                    "Appropriate masking of account details",
                    "Standard billing communication",
                    "Provides official contact methods"
                ]
            },
            nessus: {
                score: 11,
                patterns: [],
                evidence: [
                    "No malware signatures",
                    "No exploit attempts",
                    "Clean email content"
                ]
            },
            openvas: {
                score: 13,
                patterns: [],
                evidence: [
                    "No vulnerability indicators",
                    "Legitimate business communication",
                    "Standard invoice structure"
                ]
            }
        },
        ollama: {
            summary: "This is a legitimate invoice email from Deutsche Telekom. All authentication checks passed successfully, and the email follows standard billing communication practices with no phishing indicators detected.",
            reasoning: "All indicators confirm legitimacy: (1) Perfect authentication - DMARC, SPF, and DKIM all passed, confirming the email genuinely came from Telekom servers. (2) Official domain - rechnung@telekom.de is the correct domain for Telekom billing. (3) Standard format - matches typical Telekom invoice structure with customer number, invoice details, and itemized charges. (4) Appropriate data handling - IBAN is properly masked, only showing last two digits. (5) Legitimate contact information - provides official Telekom phone number and website. (6) All frameworks scored very low (9-18%) indicating minimal risk. (7) No urgency tactics, threats, or suspicious requests.",
            recommendations: [
                "Safe to read and keep for your records",
                "Verify the amount matches your expected charges",
                "Check that the payment will be processed correctly via SEPA",
                "You can log into Telekom Kundencenter to view the detailed invoice if needed",
                "Save this email for billing records and potential disputes",
                "No security action required - this is a legitimate invoice"
            ]
        }
    },

    // Email 7 - German HIGH TP - ING-DiBa Security Update Scam
    {
        id: 7,
        subject: "ING: Wichtiges Sicherheitsupdate erforderlich",
        from: "sicherheit@ing-diba-banking.com",
        language: "de",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Sehr geehrter ING-Kunde,

Im Rahmen unserer regelmäßigen Sicherheitsupdates müssen Sie Ihre Kontoinformationen aktualisieren.

NEUE EU-RICHTLINIE (PSD2):
Gemäß der neuen EU-Zahlungsdiensterichtlinie sind wir verpflichtet, Ihre Identität erneut zu verifizieren.

Was müssen Sie tun?
1. Klicken Sie auf den folgenden Link
2. Melden Sie sich mit Ihren aktuellen Zugangsdaten an
3. Bestätigen Sie Ihre persönlichen Daten
4. Aktualisieren Sie Ihre Sicherheitsfragen

Hier aktualisieren: http://ing-diba-verify.com/psd2/update?ref=DE2026

WICHTIG: Dieser Vorgang muss bis zum 12. Februar 2026 abgeschlossen sein.

Bei Nichtbeachtung:
- Ihr Online-Banking wird gesperrt
- Ihre Kreditkarten werden deaktiviert
- Überweisungen sind nicht mehr möglich

Warum ist das notwendig?
Die PSD2-Richtlinie schreibt eine verstärkte Kundenauthentifizierung vor. Ihre Sicherheit ist uns wichtig.

Vielen Dank für Ihre Mitarbeit.

Mit freundlichen Grüßen,
ING-DiBa Sicherheitsteam

ING-DiBa AG
Theodor-Heuss-Allee 2
60486 Frankfurt am Main

Mitglied der ING Groep`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 91,
                patterns: [
                    "Urgency keyword: Wichtiges",
                    "Urgency keyword: erforderlich",
                    "Urgency keyword: gesperrt",
                    "Deadline mentioned (12. Februar)",
                    "Suspicious URL detected",
                    "Multiple threat scenarios"
                ],
                evidence: [
                    "Subject creates urgency with 'Wichtiges'",
                    "Specific deadline creates pressure",
                    "Lists multiple consequences (banking, cards, transfers)",
                    "Domain ing-diba-verify.com is suspicious",
                    "Uses legitimate-sounding regulation (PSD2) as cover"
                ]
            },
            owasp: {
                score: 84,
                patterns: [
                    "Malicious redirect detected",
                    "Credential harvesting URL",
                    "Suspicious reference parameter"
                ],
                evidence: [
                    "Non-ING domain with fake PSD2 path",
                    "URL designed to collect login credentials",
                    "Reference parameter suggests tracking",
                    "HTTP instead of HTTPS for banking"
                ]
            },
            nist: {
                score: 89,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official ING uses ing.de or ing-diba.de",
                    "ing-diba-banking.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 87,
                patterns: [
                    "Sensitive data request via email",
                    "Credential update through email link",
                    "Security policy violation"
                ],
                evidence: [
                    "Requests login and personal data via email",
                    "Asks for security question updates",
                    "Legitimate banks don't request updates via email",
                    "Violates banking security standards"
                ]
            },
            nessus: {
                score: 85,
                patterns: [
                    "Known banking phishing pattern",
                    "PSD2 scam variant detected"
                ],
                evidence: [
                    "Matches known ING phishing campaigns",
                    "PSD2 is commonly used as phishing cover",
                    "Similar attacks documented in threat database"
                ]
            },
            openvas: {
                score: 86,
                patterns: [
                    "Regulatory compliance exploitation",
                    "Authority manipulation (EU directive)",
                    "Multi-threat social engineering"
                ],
                evidence: [
                    "Exploits legitimate PSD2 regulation for credibility",
                    "Uses EU authority to pressure compliance",
                    "Multiple consequences listed to increase fear",
                    "Professional formatting mimics legitimate notices"
                ]
            }
        },
        ollama: {
            summary: "This is a sophisticated phishing attack impersonating ING-DiBa bank. It exploits the legitimate EU PSD2 regulation to appear credible while attempting to steal banking credentials. The email uses multiple pressure tactics including regulatory compliance, deadlines, and service disruption threats.",
            reasoning: "Multiple critical indicators confirm this is phishing: (1) Complete authentication failure - all checks failed, indicating sender spoofing. (2) Domain spoofing - ing-diba-banking.com and ing-diba-verify.com are NOT official ING domains (official is ing.de or ing-diba.de). (3) Exploitation of legitimate regulation - uses real PSD2 directive to appear credible, but legitimate banks don't implement compliance via email links. (4) Multiple threats - banking lockout, card deactivation, transfer blocking. (5) Specific deadline (12. Februar) creates urgency. (6) All frameworks scored 84%+ indicating high risk. (7) Requests login credentials and security questions - major red flag. The professional formatting and real address inclusion are designed to appear legitimate.",
            recommendations: [
                "Delete this email immediately without clicking any links",
                "Report to ING-DiBa through their official phishing reporting system",
                "Log into ING directly through ing.de or the official app to check if any action is actually needed",
                "Never click links in emails claiming to require security updates",
                "Legitimate PSD2 compliance is handled within the banking app, not via email",
                "If you clicked the link and entered credentials, change your ING password immediately",
                "Enable two-factor authentication if not already active",
                "Monitor your account for unauthorized transactions",
                "Contact ING customer service through official channels if you have concerns",
                "Be aware that scammers often exploit legitimate regulations (like PSD2) to appear credible"
            ]
        }
    },

    // Email 8 - German MEDIUM FP - Company Internal IT Notice
    {
        id: 8,
        subject: "IT-Wartung: Systemupdate am Wochenende",
        from: "it-support@firma-intern.local",
        language: "de",
        riskLevel: "MEDIUM",
        classification: "FP",
        body: `Liebe Kolleginnen und Kollegen,

Am kommenden Wochenende (12.-13. Februar 2026) führen wir planmäßige Wartungsarbeiten an unseren IT-Systemen durch.

Betroffene Systeme:
- E-Mail-Server
- Intranet
- Fileserver
- VPN-Zugang

Zeitraum:
Samstag, 12.02.2026, 22:00 Uhr bis Sonntag, 13.02.2026, 06:00 Uhr

Während dieser Zeit können die genannten Dienste nicht genutzt werden.

Bitte beachten Sie:
- Speichern Sie alle wichtigen Dokumente vor Freitag, 17:00 Uhr
- Planen Sie keine kritischen Arbeiten für das Wochenende
- Bei dringenden Problemen: Notfall-Hotline 0123-456789

Nach Abschluss der Wartung erhalten Sie eine Bestätigungs-E-Mail.

Bei Fragen wenden Sie sich bitte an das IT-Support-Team.

Mit freundlichen Grüßen,
IT-Abteilung

Firma GmbH
IT-Support-Team
Telefon: 0123-456789
E-Mail: it-support@firma-intern.local`,
        authentication: {
            dmarc: "unknown",
            spf: "unknown",
            dkim: "unknown"
        },
        frameworks: {
            mlClassifier: {
                score: 45,
                patterns: [
                    "Urgent action mentioned (save documents)",
                    "Service disruption warning",
                    "Deadline mentioned (Freitag 17:00)"
                ],
                evidence: [
                    "Requests action before deadline",
                    "Mentions system outages",
                    "Creates time pressure",
                    "However, this is standard IT maintenance communication"
                ]
            },
            owasp: {
                score: 38,
                patterns: [
                    "No external URLs detected",
                    "Internal domain (.local)"
                ],
                evidence: [
                    "Uses internal company domain",
                    "No suspicious links",
                    "Standard IT notice format"
                ]
            },
            nist: {
                score: 52,
                patterns: [
                    "Authentication status unknown (.local domain)",
                    "Internal email system"
                ],
                evidence: [
                    "DMARC/SPF/DKIM not applicable for internal domains",
                    ".local domain indicates internal network",
                    "Cannot verify external authentication"
                ]
            },
            iso27001: {
                score: 42,
                patterns: [
                    "IT maintenance notification",
                    "Standard change management communication"
                ],
                evidence: [
                    "Follows IT maintenance notification procedures",
                    "Provides advance notice",
                    "Includes contact information",
                    "No sensitive data requests"
                ]
            },
            nessus: {
                score: 40,
                patterns: [
                    "Internal communication pattern"
                ],
                evidence: [
                    "Matches legitimate IT maintenance notices",
                    "No malware indicators",
                    "Standard corporate communication"
                ]
            },
            openvas: {
                score: 43,
                patterns: [
                    "Legitimate IT notice characteristics"
                ],
                evidence: [
                    "Professional format",
                    "Reasonable maintenance window",
                    "Provides emergency contact",
                    "No credential requests"
                ]
            }
        },
        ollama: {
            summary: "This appears to be a legitimate internal IT maintenance notification, but it was flagged as medium risk due to authentication uncertainties with internal domains and some urgency language. This is a FALSE POSITIVE - the email is actually legitimate corporate communication.",
            reasoning: "This is flagged as a false positive because: (1) Authentication unknown - internal .local domains don't use standard DMARC/SPF/DKIM, making verification difficult. (2) Some urgency language - requests document saving by deadline, which triggered ML classifier. (3) Service disruption warning - mentions system outages, which can appear suspicious. HOWEVER, legitimacy indicators: (1) Internal domain (.local) is correct for corporate networks. (2) Standard IT maintenance format - advance notice, specific timeframe, emergency contact. (3) No credential requests or suspicious links. (4) Professional language and appropriate content. (5) Framework scores are moderate (38-52%), not high risk. This demonstrates that legitimate internal communications can sometimes trigger false positives due to urgency language and authentication limitations of internal domains.",
            recommendations: [
                "This is likely a legitimate IT maintenance notice from your company",
                "Verify with your IT department if you have any doubts",
                "Follow the instructions to save important documents before the maintenance window",
                "Note the emergency hotline number for weekend issues",
                "Internal .local domains are normal for corporate networks",
                "If this is unexpected, contact IT support directly using known contact information",
                "Keep this email for reference regarding the maintenance schedule"
            ]
        }
    }

    // Email 9 - German HIGH TP - Commerzbank Transaction Verification
    {
        id: 9,
        subject: "Commerzbank: Verdächtige Transaktion erkannt",
        from: "fraud-alert@commerzbank-security.net",
        language: "de",
        riskLevel: "HIGH",
        classification: "TP",
        body: `SICHERHEITSWARNUNG

Sehr geehrter Kunde,

Wir haben eine verdächtige Transaktion auf Ihrem Konto festgestellt:

Transaktionsdetails:
Betrag: 1.247,00 EUR
Empfänger: Online Shop International Ltd.
Datum: 10. Februar 2026, 03:42 Uhr
Standort: Rumänien

War das Sie?

Falls Sie diese Transaktion NICHT autorisiert haben, müssen Sie SOFORT handeln:

1. Klicken Sie hier: http://commerzbank-verify.net/fraud/case-7849302
2. Bestätigen Sie Ihre Identität
3. Blockieren Sie die Transaktion

WICHTIG: Sie haben nur 2 Stunden Zeit, um die Transaktion zu stoppen!

Nach Ablauf dieser Frist wird der Betrag unwiderruflich überwiesen und kann nicht mehr zurückgeholt werden.

Schützen Sie Ihr Geld - Handeln Sie jetzt!

Bei Fragen: 0800-FAKE-NUM (kostenlos)

Mit freundlichen Grüßen,
Commerzbank Betrugsbekämpfung

Commerzbank AG - Ihr Partner seit 1870`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 96,
                patterns: [
                    "Urgency keyword: SICHERHEITSWARNUNG",
                    "Urgency keyword: SOFORT",
                    "Urgency keyword: nur 2 Stunden",
                    "Urgency keyword: unwiderruflich",
                    "Suspicious URL detected",
                    "Fraud alert theme",
                    "Specific transaction details (social engineering)"
                ],
                evidence: [
                    "Caps lock for SICHERHEITSWARNUNG creates panic",
                    "Extreme urgency with 2-hour deadline",
                    "Mentions specific amount (1.247 EUR) to appear legitimate",
                    "Foreign location (Rumänien) increases fear",
                    "Domain commerzbank-security.net is suspicious",
                    "Threatens irreversible loss"
                ]
            },
            owasp: {
                score: 91,
                patterns: [
                    "Malicious redirect detected",
                    "Credential harvesting URL",
                    "Fake case number parameter"
                ],
                evidence: [
                    "Non-Commerzbank domain with fraud path",
                    "URL designed to collect login credentials",
                    "Case number parameter suggests tracking",
                    "HTTP instead of HTTPS for banking"
                ]
            },
            nist: {
                score: 94,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing (commerzbank-security.net)"
                ],
                evidence: [
                    "Complete authentication failure",
                    "Official Commerzbank uses commerzbank.de",
                    "fraud-alert subdomain is suspicious",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 92,
                patterns: [
                    "Sensitive data request via email",
                    "Identity verification through email link",
                    "Fraud alert exploitation"
                ],
                evidence: [
                    "Requests identity confirmation via email",
                    "Exploits fraud prevention as cover",
                    "Legitimate banks use in-app fraud alerts",
                    "Violates banking security protocols"
                ]
            },
            nessus: {
                score: 89,
                patterns: [
                    "Known fraud alert phishing pattern",
                    "Commerzbank impersonation detected"
                ],
                evidence: [
                    "Matches documented Commerzbank phishing campaigns",
                    "Fraud alert theme is common phishing tactic",
                    "Similar attacks in threat database"
                ]
            },
            openvas: {
                score: 93,
                patterns: [
                    "Extreme urgency exploitation",
                    "Financial loss fear manipulation",
                    "False transaction details"
                ],
                evidence: [
                    "2-hour deadline creates panic",
                    "Specific transaction details appear legitimate",
                    "Foreign location (Romania) increases fear",
                    "Threatens irreversible financial loss"
                ]
            }
        },
        ollama: {
            summary: "This is a highly sophisticated phishing attack impersonating Commerzbank's fraud prevention system. It uses fake transaction details and extreme time pressure to panic the recipient into clicking a malicious link and providing their banking credentials.",
            reasoning: "This is an advanced phishing attack with multiple critical indicators: (1) Complete authentication failure - all checks failed, confirming sender spoofing. (2) Domain spoofing - commerzbank-security.net is NOT official (should be commerzbank.de). (3) Extreme urgency - 2-hour deadline is designed to bypass rational thinking. (4) Sophisticated social engineering - uses specific transaction amount (1.247 EUR), foreign location (Romania), and early morning timestamp (03:42) to appear legitimate and create fear. (5) Fraud alert exploitation - leverages legitimate security concerns to gain trust. (6) All frameworks scored 89%+ indicating unanimous high-risk assessment. (7) Legitimate banks send fraud alerts through their official app with in-app verification, never via email links. The professional formatting and historical reference ('seit 1870') are designed to appear credible.",
            recommendations: [
                "Delete this email immediately - do not click any links",
                "This is a phishing scam - there is no actual fraudulent transaction",
                "Log into Commerzbank directly through commerzbank.de or the official app to check your actual transactions",
                "Report this phishing attempt to Commerzbank and your email provider",
                "Never click links in fraud alert emails - legitimate banks use in-app notifications",
                "If you clicked the link and entered credentials, change your Commerzbank password immediately",
                "Enable two-factor authentication if not already active",
                "Monitor your account for any actual unauthorized transactions",
                "Contact Commerzbank customer service through official channels if you have concerns",
                "Be aware that scammers exploit fraud prevention fears to create panic and bypass critical thinking"
            ]
        }
    },

    // Email 10 - German LOW TN - Newsletter Subscription
    {
        id: 10,
        subject: "Ihr SPIEGEL ONLINE Newsletter",
        from: "newsletter@spiegel.de",
        language: "de",
        riskLevel: "LOW",
        classification: "TN",
        body: `Guten Tag,

hier ist Ihr täglicher Newsletter von SPIEGEL ONLINE.

TOP-THEMEN DES TAGES:

Politik:
• Bundesregierung plant neue Klimaschutzmaßnahmen
• EU-Gipfel: Diskussion über Energiepolitik

Wirtschaft:
• DAX erreicht neues Jahreshoch
• Inflation sinkt auf 2,1 Prozent

Panorama:
• Wintereinbruch in Süddeutschland
• Neues Naturschutzgebiet in Brandenburg

Sport:
• Bundesliga: Bayern München gewinnt Spitzenspiel
• Olympia-Vorbereitung läuft auf Hochtouren

Alle Artikel lesen Sie auf: www.spiegel.de

Newsletter-Einstellungen verwalten:
www.spiegel.de/newsletter/einstellungen

Abmelden:
www.spiegel.de/newsletter/abmelden

Mit freundlichen Grüßen,
Ihre SPIEGEL ONLINE Redaktion

SPIEGEL-Verlag Rudolf Augstein GmbH & Co. KG
Ericusspitze 1
20457 Hamburg

Geschäftsführung: Thomas Hass, Clemens Höges
Registergericht: Amtsgericht Hamburg, HRA 107193`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 8,
                patterns: [],
                evidence: [
                    "No urgency keywords",
                    "Standard newsletter format",
                    "News content only",
                    "Professional journalism language",
                    "No requests or calls to action beyond reading"
                ]
            },
            owasp: {
                score: 6,
                patterns: [],
                evidence: [
                    "All URLs point to official spiegel.de domain",
                    "No suspicious links",
                    "Standard newsletter structure",
                    "Proper unsubscribe link included"
                ]
            },
            nist: {
                score: 5,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain matches SPIEGEL",
                    "Perfect authentication score"
                ]
            },
            iso27001: {
                score: 7,
                patterns: [],
                evidence: [
                    "No sensitive data requests",
                    "Standard newsletter communication",
                    "Includes proper unsubscribe option (GDPR compliant)",
                    "Legitimate business information provided"
                ]
            },
            nessus: {
                score: 6,
                patterns: [],
                evidence: [
                    "No malware signatures",
                    "No exploit attempts",
                    "Clean newsletter content"
                ]
            },
            openvas: {
                score: 7,
                patterns: [],
                evidence: [
                    "No vulnerability indicators",
                    "Legitimate media newsletter",
                    "Standard news aggregation format"
                ]
            }
        },
        ollama: {
            summary: "This is a legitimate newsletter email from SPIEGEL ONLINE, one of Germany's major news publications. All authentication checks passed perfectly, and the email contains only news headlines with links to the official SPIEGEL website.",
            reasoning: "All indicators confirm this is a legitimate newsletter: (1) Perfect authentication - DMARC, SPF, and DKIM all passed, confirming the email genuinely came from SPIEGEL servers. (2) Official domain - newsletter@spiegel.de is the correct domain for SPIEGEL ONLINE. (3) Standard newsletter format - contains news headlines across multiple categories (Politics, Economy, Panorama, Sports). (4) All links point to official spiegel.de domain. (5) GDPR compliant - includes proper unsubscribe link and newsletter management options. (6) Complete business information - includes official company details, address, and registration. (7) All frameworks scored extremely low (5-8%) indicating minimal to no risk. (8) No urgency tactics, no credential requests, no suspicious elements. (9) Professional journalism language and structure.",
            recommendations: [
                "Safe to read - this is a legitimate newsletter",
                "Click on articles of interest to read full stories on spiegel.de",
                "If you no longer wish to receive this newsletter, use the unsubscribe link at the bottom",
                "You can manage your newsletter preferences through the settings link",
                "Keep this if you're interested in German news and current affairs",
                "No security action required"
            ]
        }
    },

    // Email 11 - German MEDIUM TP - WhatsApp Verification Scam
    {
        id: 11,
        subject: "WhatsApp: Bestätigen Sie Ihr Konto",
        from: "verify@whatsapp-service.com",
        language: "de",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Hallo,

Wir haben ungewöhnliche Aktivitäten von Ihrem WhatsApp-Konto festgestellt.

Ihr Konto wurde vorübergehend eingeschränkt, um Ihre Sicherheit zu gewährleisten.

Was ist passiert?
Jemand hat versucht, sich von einem unbekannten Gerät aus bei Ihrem Konto anzumelden.

Standort: Ukraine
Gerät: Android 12
Zeit: 10. Februar 2026, 04:17 Uhr

Um Ihr Konto wieder freizuschalten, bestätigen Sie bitte Ihre Telefonnummer:

Jetzt bestätigen: http://whatsapp-verify.com/account/restore

Sie müssen diesen Schritt innerhalb von 24 Stunden abschließen, sonst wird Ihr Konto dauerhaft deaktiviert und alle Ihre Chats, Kontakte und Medien werden gelöscht.

Warum ist das wichtig?
Ohne Bestätigung können wir nicht sicherstellen, dass Sie der rechtmäßige Besitzer des Kontos sind.

Vielen Dank,
WhatsApp Security Team

WhatsApp Inc.
Eine Tochtergesellschaft von Meta Platforms`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 72,
                patterns: [
                    "Urgency keyword: ungewöhnliche Aktivitäten",
                    "Urgency keyword: eingeschränkt",
                    "Urgency keyword: 24 Stunden",
                    "Urgency keyword: dauerhaft deaktiviert",
                    "Suspicious URL detected",
                    "Account verification theme"
                ],
                evidence: [
                    "Unusual activity claim creates concern",
                    "24-hour deadline creates pressure",
                    "Threatens permanent account loss",
                    "Mentions data loss (chats, contacts, media)",
                    "Domain whatsapp-service.com is suspicious",
                    "Foreign location (Ukraine) increases fear"
                ]
            },
            owasp: {
                score: 67,
                patterns: [
                    "Suspicious URL structure",
                    "Credential/phone number harvesting attempt"
                ],
                evidence: [
                    "Non-WhatsApp domain with verify path",
                    "URL designed to collect phone numbers",
                    "HTTP instead of HTTPS for account verification"
                ]
            },
            nist: {
                score: 78,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official WhatsApp uses whatsapp.com domain",
                    "whatsapp-service.com is fraudulent",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 70,
                patterns: [
                    "Phone number verification via email",
                    "Account access through email link"
                ],
                evidence: [
                    "Requests phone verification via email",
                    "WhatsApp verifies through the app, not email",
                    "Violates standard verification procedures"
                ]
            },
            nessus: {
                score: 65,
                patterns: [
                    "WhatsApp impersonation detected",
                    "Account verification scam pattern"
                ],
                evidence: [
                    "Matches known WhatsApp phishing campaigns",
                    "Verification scam is common tactic",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 69,
                patterns: [
                    "Social engineering (foreign login attempt)",
                    "Data loss threat manipulation"
                ],
                evidence: [
                    "Foreign location (Ukraine) creates fear",
                    "Threatens loss of chats and contacts",
                    "Exploits emotional attachment to data",
                    "Early morning timestamp (04:17) appears suspicious"
                ]
            }
        },
        ollama: {
            summary: "This is a medium-risk phishing email impersonating WhatsApp. It uses fake unusual activity alerts and threatens account deactivation to trick recipients into clicking a malicious link and providing their phone number, which could lead to account takeover.",
            reasoning: "Multiple indicators suggest phishing: (1) Complete authentication failure - all checks failed, indicating sender spoofing. (2) Domain spoofing - whatsapp-service.com and whatsapp-verify.com are NOT official WhatsApp domains (official is whatsapp.com). (3) Verification method - WhatsApp verifies accounts through the app itself, never via email links. (4) Urgency tactics - 24-hour deadline and threats of permanent deactivation. (5) Emotional manipulation - threatens loss of chats, contacts, and media to create panic. (6) Foreign location mention (Ukraine) increases fear. (7) Framework scores in 65-78% range indicate medium-high risk. (8) WhatsApp is owned by Meta and would use official Meta/WhatsApp domains for communication. The email is well-written but contains procedural red flags.",
            recommendations: [
                "Delete this email - it is a phishing scam",
                "Do not click the link or provide your phone number",
                "WhatsApp never sends account verification emails - all verification happens in the app",
                "Check your WhatsApp app directly if you have concerns about your account",
                "If you clicked the link, do not enter any information",
                "Enable two-step verification in WhatsApp settings for additional security",
                "Report this phishing attempt to your email provider",
                "Be aware that WhatsApp scams often target phone numbers for account takeover",
                "Legitimate WhatsApp security notifications appear only within the app"
            ]
        }
    },

    // Email 12 - German HIGH TP - Microsoft 365 Expiration Scam
    {
        id: 12,
        subject: "Microsoft 365: Ihr Abonnement läuft ab",
        from: "office@microsoft-renewal.com",
        language: "de",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Sehr geehrter Microsoft 365 Kunde,

Ihr Microsoft 365 Abonnement läuft in Kürze ab.

Abonnementdetails:
Plan: Microsoft 365 Family
Ablaufdatum: 15. Februar 2026
Lizenziert für: 6 Benutzer

WICHTIG: Verlängern Sie jetzt, um Datenverlust zu vermeiden!

Was passiert bei Ablauf?
• Zugriff auf Office-Anwendungen wird gesperrt
• OneDrive-Speicher wird auf 5 GB reduziert
• Ihre Dateien könnten gelöscht werden
• E-Mail-Zugang wird eingeschränkt
• Teams-Funktionen werden deaktiviert

Jetzt verlängern und 30% Rabatt sichern:
http://microsoft-365-renewal.com/extend?user=DE2026

Sonderangebot nur bis 12. Februar 2026 gültig!

Preis: Nur 69,99 EUR statt 99,99 EUR (Sie sparen 30 EUR)

Zahlungsmethoden:
• Kreditkarte
• PayPal
• SEPA-Lastschrift

Verlängern Sie jetzt mit einem Klick!

Bei Fragen: support@microsoft-renewal.com

Mit freundlichen Grüßen,
Microsoft 365 Team

Microsoft Corporation
One Microsoft Way
Redmond, WA 98052, USA`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 88,
                patterns: [
                    "Urgency keyword: läuft ab",
                    "Urgency keyword: WICHTIG",
                    "Urgency keyword: Datenverlust",
                    "Urgency keyword: gelöscht",
                    "Suspicious URL detected",
                    "Discount offer (social engineering)",
                    "Payment request"
                ],
                evidence: [
                    "Subscription expiration creates urgency",
                    "Threatens data loss and file deletion",
                    "Limited-time discount (30%) creates pressure",
                    "Specific deadline (12. Februar)",
                    "Domain microsoft-renewal.com is suspicious",
                    "Lists multiple consequences to increase fear"
                ]
            },
            owasp: {
                score: 82,
                patterns: [
                    "Malicious redirect to payment page",
                    "Credit card harvesting attempt",
                    "Suspicious user parameter"
                ],
                evidence: [
                    "Non-Microsoft domain with renewal path",
                    "URL designed to collect payment information",
                    "User parameter suggests tracking/targeting",
                    "HTTP instead of HTTPS for payment"
                ]
            },
            nist: {
                score: 91,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing (microsoft-renewal.com)"
                ],
                evidence: [
                    "Complete authentication failure",
                    "Official Microsoft uses microsoft.com",
                    "microsoft-renewal.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 85,
                patterns: [
                    "Payment request via email link",
                    "Subscription renewal through email",
                    "Credit card collection attempt"
                ],
                evidence: [
                    "Requests payment via email link",
                    "Microsoft handles renewals through official account portal",
                    "Violates payment security standards",
                    "Legitimate subscriptions renew automatically or through microsoft.com"
                ]
            },
            nessus: {
                score: 83,
                patterns: [
                    "Microsoft 365 phishing pattern",
                    "Subscription scam detected"
                ],
                evidence: [
                    "Matches known Microsoft phishing campaigns",
                    "Subscription expiration theme is common",
                    "Similar attacks in threat database"
                ]
            },
            openvas: {
                score: 86,
                patterns: [
                    "Data loss fear manipulation",
                    "Discount urgency exploitation",
                    "Multiple service disruption threats"
                ],
                evidence: [
                    "Threatens file deletion to create panic",
                    "30% discount creates urgency to act quickly",
                    "Lists multiple service disruptions",
                    "Combines fear (data loss) with reward (discount)"
                ]
            }
        },
        ollama: {
            summary: "This is a high-confidence phishing email impersonating Microsoft 365. It uses fake subscription expiration warnings combined with discount offers to trick recipients into clicking a malicious link and providing payment information, leading to credit card theft.",
            reasoning: "Critical phishing indicators across all frameworks: (1) Complete authentication failure - all checks failed, confirming sender spoofing. (2) Domain spoofing - microsoft-renewal.com and microsoft-365-renewal.com are NOT official Microsoft domains (official is microsoft.com). (3) Payment method - Microsoft handles subscription renewals through the official account portal at microsoft.com or through automatic billing, never via email links. (4) Multiple threats - lists numerous consequences (app lockout, storage reduction, file deletion, email restriction, Teams deactivation) to create fear. (5) Urgency tactics - expiration date, limited-time discount (30%), specific deadline. (6) All frameworks scored 82%+ indicating high risk. (7) Discount offer (30% off) is designed to make the scam appear attractive and create pressure to act quickly. The professional formatting and real Microsoft address are designed to appear legitimate, but the payment request via email link is a major red flag.",
            recommendations: [
                "Delete this email immediately - it is a phishing scam",
                "Do not click the link or provide any payment information",
                "Check your actual Microsoft 365 subscription status by logging into account.microsoft.com directly",
                "Microsoft 365 subscriptions renew automatically or can be managed only through the official Microsoft account portal",
                "Microsoft never sends renewal requests via email with payment links",
                "If you clicked the link and entered payment information, contact your bank immediately to block the card",
                "Monitor your credit card statements for unauthorized charges",
                "Report this phishing attempt to Microsoft at reportabuse@microsoft.com",
                "Enable two-factor authentication on your Microsoft account",
                "Be aware that subscription expiration scams are common for popular services like Microsoft 365, Adobe, and antivirus software"
            ]
        }
    },

    // Email 13 - German LOW TN - University Announcement
    {
        id: 13,
        subject: "Wichtige Information: Prüfungsanmeldung Sommersemester 2026",
        from: "pruefungsamt@uni-berlin.de",
        language: "de",
        riskLevel: "LOW",
        classification: "TN",
        body: `Liebe Studierende,

die Anmeldung für die Prüfungen im Sommersemester 2026 ist ab sofort möglich.

Anmeldezeitraum:
Beginn: 10. Februar 2026
Ende: 28. Februar 2026, 23:59 Uhr

Wichtige Hinweise:
• Die Anmeldung erfolgt ausschließlich über das Campus-Management-System
• Melden Sie sich rechtzeitig an - Nachmeldungen sind nicht möglich
• Überprüfen Sie Ihre Anmeldungen vor Ablauf der Frist
• Bei technischen Problemen wenden Sie sich an den IT-Support

Zugang zum System:
www.campus.uni-berlin.de

Anleitung zur Prüfungsanmeldung:
www.uni-berlin.de/studium/pruefungen/anmeldung

Prüfungszeitraum:
15. Juli 2026 bis 31. Juli 2026

Bitte beachten Sie:
• Ohne Anmeldung können Sie nicht an der Prüfung teilnehmen
• Prüfen Sie Ihre Zulassungsvoraussetzungen
• Beachten Sie eventuelle Anmeldefristen einzelner Fachbereiche

Bei Fragen wenden Sie sich bitte an:
Prüfungsamt
Telefon: 030-2093-12345
E-Mail: pruefungsamt@uni-berlin.de
Sprechzeiten: Mo-Fr 10:00-12:00 Uhr

Mit freundlichen Grüßen,
Prüfungsamt der Humboldt-Universität zu Berlin

Humboldt-Universität zu Berlin
Unter den Linden 6
10099 Berlin`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 22,
                patterns: [
                    "Deadline mentioned (administrative, not threatening)"
                ],
                evidence: [
                    "Contains deadline but in administrative context",
                    "Standard university communication format",
                    "No urgency beyond normal academic deadlines",
                    "Professional academic language",
                    "No suspicious requests"
                ]
            },
            owasp: {
                score: 14,
                patterns: [],
                evidence: [
                    "All URLs point to official uni-berlin.de domain",
                    "No suspicious links",
                    "Standard university portal references",
                    "Proper institutional communication"
                ]
            },
            nist: {
                score: 11,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain matches university",
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 16,
                patterns: [],
                evidence: [
                    "No sensitive data requests",
                    "Standard administrative communication",
                    "Directs to official university systems",
                    "Provides proper contact information"
                ]
            },
            nessus: {
                score: 13,
                patterns: [],
                evidence: [
                    "No malware signatures",
                    "No exploit attempts",
                    "Clean institutional email"
                ]
            },
            openvas: {
                score: 15,
                patterns: [],
                evidence: [
                    "No vulnerability indicators",
                    "Legitimate university communication",
                    "Standard academic administration format"
                ]
            }
        },
        ollama: {
            summary: "This is a legitimate administrative email from Humboldt-Universität zu Berlin regarding exam registration for the summer semester 2026. All authentication checks passed, and the email follows standard university communication practices.",
            reasoning: "All indicators confirm legitimacy: (1) Perfect authentication - DMARC, SPF, and DKIM all passed, confirming the email genuinely came from university servers. (2) Official domain - pruefungsamt@uni-berlin.de is the correct domain for the university's examination office. (3) Standard format - matches typical university administrative announcements with clear dates, procedures, and contact information. (4) All links point to official uni-berlin.de domain. (5) Professional academic language and structure. (6) Provides complete contact information including phone, email, and office hours. (7) All frameworks scored very low (11-22%) indicating minimal risk. (8) The deadline mentioned is a normal administrative deadline, not a threatening urgency tactic. (9) Directs students to official campus management system, not external links.",
            recommendations: [
                "Safe to read - this is a legitimate university announcement",
                "Log into the campus management system at campus.uni-berlin.de to register for exams",
                "Note the registration deadline (28. Februar 2026) and register on time",
                "Follow the provided instructions for exam registration",
                "Contact the Prüfungsamt if you have questions using the provided contact information",
                "Keep this email for reference regarding exam registration dates",
                "No security action required"
            ]
        }
    },

    // Email 14 - German MEDIUM TP - Netflix Payment Failure Scam
    {
        id: 14,
        subject: "Netflix: Problem mit Ihrer Zahlung",
        from: "billing@netflix-service.net",
        language: "de",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Hallo,

Wir konnten Ihre letzte Zahlung nicht verarbeiten.

Ihr Netflix-Konto wurde vorübergehend pausiert.

Problem: Zahlung fehlgeschlagen
Betrag: 12,99 EUR
Datum: 10. Februar 2026

Um Ihr Konto zu reaktivieren, aktualisieren Sie bitte Ihre Zahlungsinformationen:

Zahlungsmethode aktualisieren: http://netflix-billing.net/update-payment

Was Sie erwartet:
• Ihr Konto bleibt für 7 Tage pausiert
• Danach wird es automatisch gekündigt
• Sie verlieren Zugriff auf Ihre Profile und Listen
• Ihre Sehgewohnheiten und Empfehlungen gehen verloren

Aktualisieren Sie jetzt, um weiterzuschauen!

Beliebte Serien warten auf Sie:
• Stranger Things - Neue Staffel
• The Crown - Finale
• Wednesday - Staffel 2

Verpassen Sie nichts!

Bei Fragen: help@netflix-service.net

Viel Spaß beim Streamen,
Das Netflix-Team

Netflix International B.V.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 70,
                patterns: [
                    "Urgency keyword: Problem",
                    "Urgency keyword: pausiert",
                    "Urgency keyword: gekündigt",
                    "Urgency keyword: verlieren",
                    "Suspicious URL detected",
                    "Payment update request",
                    "FOMO tactics (popular series)"
                ],
                evidence: [
                    "Payment failure creates concern",
                    "7-day deadline before cancellation",
                    "Threatens loss of profiles and data",
                    "Domain netflix-service.net is suspicious",
                    "Uses FOMO with popular series mentions",
                    "Specific amount (12,99 EUR) appears legitimate"
                ]
            },
            owasp: {
                score: 65,
                patterns: [
                    "Payment information harvesting",
                    "Credit card collection attempt",
                    "Suspicious billing domain"
                ],
                evidence: [
                    "Non-Netflix domain with billing path",
                    "URL designed to collect payment information",
                    "HTTP instead of HTTPS for payment update"
                ]
            },
            nist: {
                score: 76,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Netflix uses netflix.com",
                    "netflix-service.net is fraudulent",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 68,
                patterns: [
                    "Payment update via email link",
                    "Credit card request through email"
                ],
                evidence: [
                    "Requests payment update via email",
                    "Netflix handles billing through official app/website",
                    "Violates payment security practices"
                ]
            },
            nessus: {
                score: 64,
                patterns: [
                    "Netflix payment scam pattern",
                    "Subscription service impersonation"
                ],
                evidence: [
                    "Matches known Netflix phishing campaigns",
                    "Payment failure theme is common",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 67,
                patterns: [
                    "FOMO exploitation (Fear of Missing Out)",
                    "Entertainment service disruption threat",
                    "Data loss manipulation"
                ],
                evidence: [
                    "Mentions popular series to create FOMO",
                    "Threatens loss of profiles and recommendations",
                    "7-day deadline creates urgency",
                    "Exploits entertainment dependency"
                ]
            }
        },
        ollama: {
            summary: "This is a medium-risk phishing email impersonating Netflix. It uses fake payment failure notifications and FOMO tactics (mentioning popular series) to trick recipients into clicking a malicious link and providing credit card information.",
            reasoning: "Multiple indicators suggest phishing: (1) Complete authentication failure - all checks failed, indicating sender spoofing. (2) Domain spoofing - netflix-service.net and netflix-billing.net are NOT official Netflix domains (official is netflix.com). (3) Payment method - Netflix handles billing through the official app or website, never via email links. (4) FOMO tactics - mentions popular series (Stranger Things, The Crown, Wednesday) to create fear of missing out. (5) Urgency - 7-day deadline before cancellation. (6) Threatens data loss (profiles, viewing history, recommendations). (7) Framework scores in 64-76% range indicate medium-high risk. (8) The email is well-written and uses Netflix's casual tone, making it more convincing. The specific price (12,99 EUR) matches actual Netflix pricing, adding to the illusion of legitimacy.",
            recommendations: [
                "Delete this email - it is a phishing scam",
                "Do not click the link or provide any payment information",
                "Check your actual Netflix account status by logging into netflix.com or the official app",
                "Netflix sends payment notifications through the app and official website, not via email links",
                "If you clicked the link and entered payment information, contact your bank immediately",
                "Monitor your credit card statements for unauthorized charges",
                "Report this phishing attempt to Netflix and your email provider",
                "Enable two-factor authentication on your Netflix account if available",
                "Be aware that streaming service payment scams are increasingly common for Netflix, Disney+, Spotify, etc."
            ]
        }
    },

    // Email 15 - German HIGH FN - Sophisticated CEO Fraud
    {
        id: 15,
        subject: "Re: Vertraulich - Dringende Überweisung",
        from: "ceo@firma-gmbh.de",
        language: "de",
        riskLevel: "HIGH",
        classification: "FN",
        body: `Guten Morgen,

ich bin gerade in einer wichtigen Verhandlung in Zürich und kann nicht telefonieren.

Wir müssen heute noch eine dringende Zahlung an einen neuen Lieferanten tätigen. Die Rechtsabteilung hat alles geprüft.

Empfänger: Swiss Trading Solutions AG
IBAN: CH93 0076 2011 6238 5295 7
Betrag: 47.500 EUR
Verwendungszweck: Anzahlung Projekt Alpenblick

Bitte veranlassen Sie die Überweisung bis 14:00 Uhr. Der Lieferant benötigt die Bestätigung noch heute.

Ich bin ab 16:00 Uhr wieder erreichbar.

Vielen Dank für Ihre Unterstützung.

Mit freundlichen Grüßen,
Dr. Michael Schneider
Geschäftsführer

Firma GmbH
Musterstraße 45
80333 München

Gesendet von meinem iPhone`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 35,
                patterns: [
                    "Urgency keyword: dringende",
                    "Urgency keyword: heute noch",
                    "Deadline mentioned (14:00 Uhr)",
                    "Payment request"
                ],
                evidence: [
                    "Requests urgent payment",
                    "Specific deadline (14:00 Uhr)",
                    "However, appears to be from legitimate company domain",
                    "Professional business language",
                    "Reasonable business context (supplier payment)"
                ]
            },
            owasp: {
                score: 28,
                patterns: [],
                evidence: [
                    "No suspicious URLs",
                    "No external links",
                    "Standard business email format",
                    "Company domain appears legitimate"
                ]
            },
            nist: {
                score: 18,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain matches company",
                    "All authentication checks passed"
                ]
            },
            iso27001: {
                score: 42,
                patterns: [
                    "Financial transaction via email",
                    "Bypasses normal approval process"
                ],
                evidence: [
                    "Requests payment via email",
                    "Mentions CEO is unavailable (bypasses verification)",
                    "However, could be legitimate urgent business need",
                    "Professional context provided"
                ]
            },
            nessus: {
                score: 30,
                patterns: [
                    "CEO fraud pattern indicators"
                ],
                evidence: [
                    "CEO urgency theme is common in fraud",
                    "However, authentication passed",
                    "Could be legitimate business communication"
                ]
            },
            openvas: {
                score: 38,
                patterns: [
                    "Authority exploitation (CEO position)",
                    "Urgency with limited availability"
                ],
                evidence: [
                    "Uses CEO authority to pressure action",
                    "Claims unavailability to prevent verification",
                    "However, context seems reasonable",
                    "Professional business scenario"
                ]
            }
        },
        ollama: {
            summary: "This is a FALSE NEGATIVE - a sophisticated CEO fraud (Business Email Compromise) that appears legitimate due to passed authentication but is actually a scam. The attacker has compromised the CEO's email account or is using a very similar domain. This type of attack is extremely dangerous because it passes technical checks.",
            reasoning: "This is classified as a FALSE NEGATIVE because it appears legitimate but is actually fraud: (1) Authentication passed - DMARC, SPF, DKIM all passed, suggesting either the CEO's account was compromised or a very similar domain is being used. (2) CEO fraud indicators - urgent payment request, CEO claims to be unavailable, bypasses normal approval processes, specific deadline. (3) Low framework scores (18-42%) suggest legitimacy, which is why this is dangerous. (4) Professional language and reasonable business context make it convincing. (5) 'Sent from iPhone' adds authenticity. (6) Swiss IBAN and specific project name appear legitimate. (7) Amount (47.500 EUR) is significant but not suspiciously large. This demonstrates that sophisticated Business Email Compromise attacks can pass all technical checks, requiring human verification through secondary channels.",
            recommendations: [
                "DO NOT process this payment based solely on this email",
                "Verify this request through a secondary channel - call the CEO directly on their known phone number",
                "Check if 'Swiss Trading Solutions AG' is a known/verified supplier",
                "Verify the IBAN with your finance department",
                "Check if 'Projekt Alpenblick' is a real project in your company",
                "Follow your company's payment approval procedures - do not bypass them",
                "Be suspicious of urgent payment requests that bypass normal processes",
                "Even if authentication passes, CEO fraud can occur through compromised accounts",
                "Implement dual authorization for payments above certain thresholds",
                "If this is legitimate, the CEO will understand the need for verification",
                "Report this to your IT security team for investigation"
            ]
        }
    },

    // Email 16 - German MEDIUM FP - Legitimate Security Alert Flagged
    {
        id: 16,
        subject: "Sicherheitshinweis: Neue Anmeldung erkannt",
        from: "no-reply@accounts.google.com",
        language: "de",
        riskLevel: "MEDIUM",
        classification: "FP",
        body: `Hallo,

Wir haben eine neue Anmeldung in Ihrem Google-Konto festgestellt.

Gerät: Windows PC
Standort: Berlin, Deutschland
Zeit: 10. Februar 2026, 09:15 Uhr
Browser: Chrome 121

Waren Sie das?

Wenn Sie sich gerade angemeldet haben, können Sie diese E-Mail ignorieren.

Falls Sie diese Aktivität nicht erkennen:
1. Sichern Sie Ihr Konto unter myaccount.google.com/security
2. Ändern Sie Ihr Passwort
3. Überprüfen Sie Ihre Sicherheitseinstellungen

Ihr Konto schützen:
• Verwenden Sie ein sicheres, einzigartiges Passwort
• Aktivieren Sie die Bestätigung in zwei Schritten
• Überprüfen Sie regelmäßig Ihre Kontoaktivität

Weitere Informationen:
https://support.google.com/accounts/answer/6294825

Diese E-Mail wurde automatisch gesendet. Bitte antworten Sie nicht darauf.

Mit freundlichen Grüßen,
Das Google-Team

Google Ireland Limited
Gordon House, Barrow Street
Dublin 4, Irland`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 48,
                patterns: [
                    "Security alert theme",
                    "New login detected",
                    "Action recommended (password change)"
                ],
                evidence: [
                    "Security alert creates concern",
                    "Mentions unrecognized activity",
                    "Recommends password change",
                    "However, this is standard Google security notification",
                    "Professional format and language"
                ]
            },
            owasp: {
                score: 35,
                patterns: [
                    "Links to Google domains"
                ],
                evidence: [
                    "All URLs point to official google.com domains",
                    "myaccount.google.com is legitimate",
                    "support.google.com is legitimate",
                    "No suspicious links"
                ]
            },
            nist: {
                score: 22,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain is official Google",
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 40,
                patterns: [
                    "Security notification",
                    "Password change recommendation"
                ],
                evidence: [
                    "Standard security alert format",
                    "Directs to official Google account security page",
                    "Follows security best practices",
                    "No direct credential requests"
                ]
            },
            nessus: {
                score: 38,
                patterns: [
                    "Security alert pattern"
                ],
                evidence: [
                    "Matches legitimate Google security alerts",
                    "However, security alerts can be phishing vectors",
                    "This appears genuine based on authentication"
                ]
            },
            openvas: {
                score: 42,
                patterns: [
                    "Account security concern",
                    "Unrecognized activity theme"
                ],
                evidence: [
                    "Creates concern about account security",
                    "However, this is legitimate Google practice",
                    "Professional and informative tone",
                    "Provides helpful security recommendations"
                ]
            }
        },
        ollama: {
            summary: "This is a FALSE POSITIVE - a legitimate security notification from Google that was flagged as medium risk due to security alert language and action recommendations. The email is actually genuine and serves to protect user accounts.",
            reasoning: "This is classified as a FALSE POSITIVE because: (1) Perfect authentication - DMARC, SPF, DKIM all passed, confirming it genuinely came from Google. (2) Official domain - no-reply@accounts.google.com is the correct domain for Google account notifications. (3) All links point to legitimate google.com domains (myaccount.google.com, support.google.com). (4) Standard format - matches typical Google security alerts. (5) Framework scores are moderate (22-48%) due to security alert language triggering ML patterns. (6) The email creates concern (new login detected) and recommends action (password change), which are common phishing tactics, but in this case it's legitimate security practice. (7) Professional language and appropriate security recommendations. This demonstrates that legitimate security alerts can trigger false positives because they share characteristics with phishing emails (urgency, security concerns, action requests).",
            recommendations: [
                "This is a legitimate Google security notification",
                "If you just logged in from Berlin with Windows/Chrome, you can ignore this email",
                "If you don't recognize this activity, follow Google's recommendations",
                "Visit myaccount.google.com/security directly (don't click email links if unsure) to review account activity",
                "Change your password if you suspect unauthorized access",
                "Enable two-factor authentication for additional security",
                "Regularly review your Google account activity",
                "Keep this email for your records",
                "Google legitimately sends these alerts to protect your account",
                "To distinguish legitimate Google alerts from phishing: check authentication, verify all links point to google.com, and note that Google never asks for passwords in emails"
            ]
        }
    }

    // Email 17 - German HIGH TP - Apple ID Account Lock
    {
        id: 17,
        subject: "Ihr Apple ID wurde gesperrt",
        from: "security@apple-id-support.com",
        language: "de",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Sehr geehrter Apple-Kunde,

Wir haben verdächtige Aktivitäten in Ihrem Apple ID-Konto festgestellt.

Zu Ihrer Sicherheit wurde Ihr Konto vorübergehend gesperrt.

Erkannte Probleme:
• Anmeldeversuch von unbekanntem Gerät (iPhone 15 Pro)
• Standort: Russland, Moskau
• Datum: 10. Februar 2026, 02:34 Uhr
• Mehrere fehlgeschlagene Passwortversuche

Betroffene Dienste:
✗ iCloud
✗ App Store
✗ Apple Music
✗ iMessage und FaceTime
✗ Find My iPhone

SOFORTIGE AKTION ERFORDERLICH:

Bestätigen Sie Ihre Identität innerhalb von 24 Stunden:
http://appleid-verify.com/unlock?case=APL-2026-7849

Nach Ablauf der Frist:
• Ihr Konto wird dauerhaft deaktiviert
• Alle iCloud-Daten werden gelöscht
• Gekaufte Apps und Medien gehen verloren
• Ihr iPhone wird aus der Ferne gesperrt

Schützen Sie Ihre Daten jetzt!

Apple Support Team
Apple Distribution International Ltd.
Hollyhill Industrial Estate
Cork, Irland

Apple ID | Datenschutz | Nutzungsbedingungen`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 93,
                patterns: [
                    "Urgency keyword: gesperrt",
                    "Urgency keyword: SOFORTIGE AKTION",
                    "Urgency keyword: 24 Stunden",
                    "Urgency keyword: dauerhaft deaktiviert",
                    "Urgency keyword: gelöscht",
                    "Suspicious URL detected",
                    "Multiple threat scenarios"
                ],
                evidence: [
                    "Account lock creates immediate concern",
                    "24-hour deadline creates pressure",
                    "Lists multiple service disruptions",
                    "Threatens data deletion and device lock",
                    "Domain apple-id-support.com is suspicious",
                    "Foreign location (Russia) increases fear",
                    "Early morning timestamp (02:34) appears suspicious"
                ]
            },
            owasp: {
                score: 87,
                patterns: [
                    "Malicious redirect detected",
                    "Credential harvesting attempt",
                    "Suspicious case parameter"
                ],
                evidence: [
                    "Non-Apple domain with unlock path",
                    "URL designed to collect Apple ID credentials",
                    "Case parameter suggests tracking",
                    "HTTP instead of HTTPS for account security"
                ]
            },
            nist: {
                score: 91,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "Complete authentication failure",
                    "Official Apple uses apple.com or icloud.com",
                    "apple-id-support.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 89,
                patterns: [
                    "Identity verification via email link",
                    "Account unlock through email",
                    "Security policy violation"
                ],
                evidence: [
                    "Requests identity confirmation via email",
                    "Apple handles account security through official website/app",
                    "Violates Apple's security procedures",
                    "Legitimate Apple never unlocks accounts via email links"
                ]
            },
            nessus: {
                score: 86,
                patterns: [
                    "Apple ID phishing pattern",
                    "Account lock scam detected"
                ],
                evidence: [
                    "Matches known Apple phishing campaigns",
                    "Account lock theme is common tactic",
                    "Similar attacks documented in threat database"
                ]
            },
            openvas: {
                score: 90,
                patterns: [
                    "Data loss fear manipulation",
                    "Multiple service disruption threats",
                    "Device lock threat"
                ],
                evidence: [
                    "Threatens deletion of iCloud data",
                    "Lists multiple service disruptions (iCloud, App Store, Music, Messages)",
                    "Threatens remote device lock",
                    "Foreign location (Russia) creates fear",
                    "Combines multiple fears: data loss, service disruption, device lock"
                ]
            }
        },
        ollama: {
            summary: "This is a high-confidence phishing email impersonating Apple. It uses sophisticated social engineering with fake security alerts, foreign login attempts, and multiple threat scenarios to panic the recipient into clicking a malicious link and providing their Apple ID credentials.",
            reasoning: "Critical phishing indicators across all frameworks: (1) Complete authentication failure - all checks failed, confirming sender spoofing. (2) Domain spoofing - apple-id-support.com and appleid-verify.com are NOT official Apple domains (official is apple.com or icloud.com). (3) Multiple threats - account deactivation, data deletion, app loss, device remote lock. (4) Extreme urgency - 24-hour deadline with severe consequences. (5) Foreign location (Russia, Moscow) creates fear and appears threatening. (6) All frameworks scored 86%+ indicating unanimous high-risk assessment. (7) Apple handles account security exclusively through appleid.apple.com or the official Apple Support app, never via email links. (8) The professional formatting with legal footer and service marks is designed to appear legitimate. The email exploits fear of losing valuable data (photos, documents, purchases) stored in iCloud.",
            recommendations: [
                "Delete this email immediately - it is a phishing scam",
                "Do not click any links or provide your Apple ID credentials",
                "Check your actual Apple ID status by visiting appleid.apple.com directly",
                "Apple never sends account unlock requests via email",
                "If you have concerns, use the official Apple Support app or visit an Apple Store",
                "If you clicked the link and entered credentials, change your Apple ID password immediately at appleid.apple.com",
                "Enable two-factor authentication on your Apple ID for additional security",
                "Review your Apple ID security settings and connected devices",
                "Report this phishing attempt to Apple at reportphishing@apple.com",
                "Monitor your Apple account for any unauthorized activity or purchases",
                "Be aware that Apple ID phishing is extremely common due to the value of iCloud data and linked payment methods"
            ]
        }
    },

    // Email 18 - German MEDIUM TP - LinkedIn Profile View Bait
    {
        id: 18,
        subject: "15 Personen haben Ihr Profil angesehen",
        from: "notifications@linkedin-mail.com",
        language: "de",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Hallo Max,

Ihr LinkedIn-Profil wird immer beliebter!

In den letzten 7 Tagen haben 15 Personen Ihr Profil angesehen.

Wer hat Ihr Profil besucht?
• Personalmanager bei Siemens AG
• Senior Recruiter bei BMW Group
• CEO bei Tech Startup Berlin
• 12 weitere Personen

Sehen Sie, wer sich für Sie interessiert:
http://linkedin-profile.com/who-viewed?user=max-mustermann

Premium-Mitglieder können alle Profilbesucher sehen!

Jetzt upgraden und Ihre Karrierechancen verbessern:
• Sehen Sie alle Profilbesucher
• Erhalten Sie InMail-Nachrichten
• Erscheinen Sie in mehr Suchergebnissen
• Zugang zu LinkedIn Learning

Nur heute: 30% Rabatt auf Premium!
Regulär 59,99 EUR/Monat - Jetzt nur 41,99 EUR/Monat

Angebot gilt nur bis 23:59 Uhr heute!

Jetzt upgraden: http://linkedin-premium.com/upgrade

Verpassen Sie keine Karrierechance!

Das LinkedIn-Team

LinkedIn Ireland Unlimited Company
Wilton Plaza, Wilton Place
Dublin 2, Irland

Einstellungen | Hilfe | Datenschutz`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 66,
                patterns: [
                    "Urgency keyword: Nur heute",
                    "Urgency keyword: nur bis 23:59 Uhr",
                    "Urgency keyword: Verpassen Sie keine",
                    "Suspicious URL detected",
                    "Discount offer (30%)",
                    "FOMO tactics (career opportunities)"
                ],
                evidence: [
                    "Profile view notification creates curiosity",
                    "Limited-time discount (30%) creates pressure",
                    "Same-day deadline (23:59 Uhr)",
                    "Domain linkedin-mail.com is suspicious",
                    "Mentions specific companies (Siemens, BMW) to appear legitimate",
                    "FOMO with career opportunities"
                ]
            },
            owasp: {
                score: 61,
                patterns: [
                    "Suspicious URL structure",
                    "Payment page redirect",
                    "User tracking parameter"
                ],
                evidence: [
                    "Non-LinkedIn domains (linkedin-profile.com, linkedin-premium.com)",
                    "URLs designed to collect payment information",
                    "User parameter suggests targeting",
                    "HTTP instead of HTTPS for payment"
                ]
            },
            nist: {
                score: 73,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official LinkedIn uses linkedin.com",
                    "linkedin-mail.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 64,
                patterns: [
                    "Payment request via email link",
                    "Subscription upgrade through email"
                ],
                evidence: [
                    "Requests payment via email link",
                    "LinkedIn handles subscriptions through official website",
                    "Violates payment security practices"
                ]
            },
            nessus: {
                score: 60,
                patterns: [
                    "LinkedIn impersonation detected",
                    "Profile view scam pattern"
                ],
                evidence: [
                    "Matches known LinkedIn phishing campaigns",
                    "Profile view theme is common tactic",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 63,
                patterns: [
                    "FOMO exploitation (career opportunities)",
                    "Curiosity manipulation (who viewed profile)",
                    "Discount urgency"
                ],
                evidence: [
                    "Exploits professional curiosity about profile viewers",
                    "Mentions prestigious companies to create interest",
                    "30% discount creates urgency",
                    "Same-day deadline increases pressure",
                    "Leverages career advancement fears"
                ]
            }
        },
        ollama: {
            summary: "This is a medium-risk phishing email impersonating LinkedIn. It exploits professional curiosity about profile viewers and career opportunities to trick recipients into clicking malicious links and providing payment information for a fake Premium upgrade.",
            reasoning: "Multiple indicators suggest phishing: (1) Complete authentication failure - all checks failed, indicating sender spoofing. (2) Domain spoofing - linkedin-mail.com, linkedin-profile.com, and linkedin-premium.com are NOT official LinkedIn domains (official is linkedin.com). (3) FOMO tactics - exploits curiosity about who viewed your profile and mentions prestigious companies (Siemens, BMW). (4) Urgency - same-day deadline (23:59 Uhr) and limited-time discount (30%). (5) Payment request - directs to fake payment page for Premium subscription. (6) Framework scores in 60-73% range indicate medium-high risk. (7) LinkedIn does send profile view notifications, but only through the official app/website, never with external payment links. The email is well-crafted and uses realistic LinkedIn language, making it more convincing than obvious scams.",
            recommendations: [
                "Delete this email - it is a phishing scam",
                "Do not click any links or provide payment information",
                "Check actual profile views by logging into linkedin.com or the official app",
                "LinkedIn sends notifications through the app and official website, not via email with payment links",
                "If you want LinkedIn Premium, subscribe only through the official LinkedIn website",
                "If you clicked the link and entered payment information, contact your bank immediately",
                "Monitor your credit card statements for unauthorized charges",
                "Report this phishing attempt to LinkedIn and your email provider",
                "Enable two-factor authentication on your LinkedIn account",
                "Be aware that professional networking scams exploit career ambitions and FOMO about opportunities"
            ]
        }
    },

    // Email 19 - German LOW TN - Deutsche Post Tracking Update
    {
        id: 19,
        subject: "Ihre Sendung ist unterwegs",
        from: "paket@deutschepost.de",
        language: "de",
        riskLevel: "LOW",
        classification: "TN",
        body: `Guten Tag,

Ihre Sendung ist auf dem Weg zu Ihnen.

Sendungsnummer: 00340434161234567890
Versender: Amazon Logistik
Empfänger: Max Mustermann

Aktueller Status: In Zustellung
Voraussichtliche Zustellung: Heute, 10. Februar 2026

Sendungsverlauf:
09.02.2026, 18:45 - Sendung im Paketzentrum Berlin
10.02.2026, 06:30 - Sendung im Zustellstützpunkt
10.02.2026, 09:15 - Sendung in Zustellung

Ihre Sendung wird heute zwischen 10:00 und 18:00 Uhr zugestellt.

Sendung verfolgen:
www.deutschepost.de/sendungsverfolgung?piececode=00340434161234567890

Nicht zu Hause?
• Sendung an Packstation umleiten
• Nachbar als Empfänger hinterlegen
• Abstellgenehmigung erteilen

Alle Optionen: www.deutschepost.de/empfangsoptionen

Bei Fragen:
Kundenservice: 0228 4333112
Online-Hilfe: www.deutschepost.de/hilfe

Mit freundlichen Grüßen,
Deutsche Post AG

Deutsche Post AG
Charles-de-Gaulle-Straße 20
53113 Bonn`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 16,
                patterns: [],
                evidence: [
                    "No urgency keywords",
                    "Standard tracking notification format",
                    "Professional logistics language",
                    "Provides tracking history",
                    "No suspicious requests"
                ]
            },
            owasp: {
                score: 11,
                patterns: [],
                evidence: [
                    "All URLs point to official deutschepost.de domain",
                    "No suspicious links",
                    "Standard tracking format",
                    "Proper delivery notification"
                ]
            },
            nist: {
                score: 9,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain matches Deutsche Post",
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 13,
                patterns: [],
                evidence: [
                    "No sensitive data requests",
                    "Standard delivery communication",
                    "Provides legitimate tracking options",
                    "Appropriate contact information"
                ]
            },
            nessus: {
                score: 10,
                patterns: [],
                evidence: [
                    "No malware signatures",
                    "No exploit attempts",
                    "Clean tracking notification"
                ]
            },
            openvas: {
                score: 12,
                patterns: [],
                evidence: [
                    "No vulnerability indicators",
                    "Legitimate postal service communication",
                    "Standard tracking update format"
                ]
            }
        },
        ollama: {
            summary: "This is a legitimate package tracking notification from Deutsche Post. All authentication checks passed perfectly, and the email follows standard delivery notification practices with proper tracking information and official links.",
            reasoning: "All indicators confirm legitimacy: (1) Perfect authentication - DMARC, SPF, and DKIM all passed, confirming the email genuinely came from Deutsche Post servers. (2) Official domain - paket@deutschepost.de is the correct domain for Deutsche Post tracking notifications. (3) Standard format - includes proper tracking number, sender/recipient information, delivery timeline, and tracking history. (4) All links point to official deutschepost.de domain. (5) Professional logistics language and structure. (6) Provides helpful delivery options (Packstation, neighbor delivery, drop-off authorization). (7) Complete contact information with official customer service number. (8) All frameworks scored very low (9-16%) indicating minimal risk. (9) No urgency tactics, no payment requests, no suspicious elements. (10) Tracking number format matches Deutsche Post standards.",
            recommendations: [
                "Safe to read - this is a legitimate tracking notification",
                "Your package is scheduled for delivery today between 10:00-18:00",
                "Use the tracking link to monitor real-time delivery status",
                "Consider setting up delivery options if you won't be home",
                "Keep this email for reference if delivery issues arise",
                "The tracking number can be used on the Deutsche Post website or app",
                "No security action required"
            ]
        }
    },

    // Email 20 - German HIGH TP - Postbank Verification Scam
    {
        id: 20,
        subject: "Postbank: Verifizierung ausstehend",
        from: "kundenservice@postbank-online.net",
        language: "de",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Sehr geehrter Postbank-Kunde,

Gemäß den neuen EU-Geldwäschevorschriften müssen wir Ihre Identität erneut verifizieren.

Ihr Online-Banking-Zugang wurde vorübergehend eingeschränkt.

Erforderliche Maßnahmen:
1. Identitätsverifizierung durchführen
2. Persönliche Daten aktualisieren
3. Neue Sicherheitsfragen festlegen

Jetzt verifizieren: http://postbank-verify.net/id-check?ref=PB2026

WICHTIG: Verifizierung bis 12. Februar 2026 erforderlich!

Bei Nichtdurchführung:
• Ihr Konto wird vollständig gesperrt
• Überweisungen sind nicht möglich
• Daueraufträge werden gestoppt
• Lastschriften werden abgelehnt
• Kreditkarten werden deaktiviert

Warum ist das notwendig?
Die EU-Geldwäscherichtlinie (5AMLD) schreibt eine regelmäßige Kundenidentifizierung vor.

Betroffene Konten:
Girokonto: DE89 1001 0010 **** **34
Sparkonto: DE89 1001 0010 **** **67

Verifizierung dauert nur 3 Minuten!

Vielen Dank für Ihre Mitarbeit im Kampf gegen Geldwäsche.

Mit freundlichen Grüßen,
Postbank Kundenservice

Deutsche Postbank AG
Friedrich-Ebert-Allee 114-126
53113 Bonn

Mitglied der Deutsche Bank Gruppe`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 90,
                patterns: [
                    "Urgency keyword: ausstehend",
                    "Urgency keyword: eingeschränkt",
                    "Urgency keyword: WICHTIG",
                    "Urgency keyword: vollständig gesperrt",
                    "Deadline mentioned (12. Februar)",
                    "Suspicious URL detected",
                    "Multiple threat scenarios"
                ],
                evidence: [
                    "Verification requirement creates urgency",
                    "Specific deadline (12. Februar)",
                    "Lists multiple consequences (transfers, standing orders, direct debits, cards)",
                    "Domain postbank-online.net is suspicious",
                    "Uses legitimate-sounding regulation (5AMLD) as cover",
                    "Shows partial account numbers to appear legitimate"
                ]
            },
            owasp: {
                score: 84,
                patterns: [
                    "Malicious redirect detected",
                    "Identity theft attempt",
                    "Credential harvesting URL"
                ],
                evidence: [
                    "Non-Postbank domain with verification path",
                    "URL designed to collect personal information and credentials",
                    "Reference parameter suggests tracking",
                    "HTTP instead of HTTPS for banking"
                ]
            },
            nist: {
                score: 89,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Postbank uses postbank.de",
                    "postbank-online.net is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 87,
                patterns: [
                    "Identity verification via email link",
                    "Personal data update through email",
                    "Security policy violation"
                ],
                evidence: [
                    "Requests identity verification via email",
                    "Asks for personal data updates",
                    "Legitimate banks verify identity through secure in-app processes",
                    "Violates banking security standards"
                ]
            },
            nessus: {
                score: 85,
                patterns: [
                    "Postbank phishing pattern",
                    "Regulatory compliance exploitation"
                ],
                evidence: [
                    "Matches known Postbank phishing campaigns",
                    "5AMLD regulation exploitation is common tactic",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 86,
                patterns: [
                    "Regulatory compliance exploitation",
                    "Authority manipulation (EU directive)",
                    "Multiple service disruption threats"
                ],
                evidence: [
                    "Exploits legitimate 5AMLD regulation for credibility",
                    "Uses EU authority to pressure compliance",
                    "Lists multiple consequences to increase fear",
                    "Shows partial account numbers to appear legitimate",
                    "Mentions quick process (3 minutes) to reduce hesitation"
                ]
            }
        },
        ollama: {
            summary: "This is a high-confidence phishing attack impersonating Postbank. It exploits the legitimate EU Anti-Money Laundering Directive (5AMLD) to appear credible while attempting to steal banking credentials and personal information through a fraudulent verification process.",
            reasoning: "Critical phishing indicators across all frameworks: (1) Complete authentication failure - all checks failed, confirming sender spoofing. (2) Domain spoofing - postbank-online.net and postbank-verify.net are NOT official Postbank domains (official is postbank.de). (3) Regulatory exploitation - uses real 5AMLD directive to appear credible, but legitimate banks don't implement compliance via email links. (4) Multiple threats - account lockout, transfer blocking, standing order cancellation, direct debit rejection, card deactivation. (5) Specific deadline (12. Februar) creates urgency. (6) All frameworks scored 84%+ indicating unanimous high-risk assessment. (7) Shows partial account numbers (masked IBANs) to appear legitimate and create personal connection. (8) Requests identity verification and personal data updates - major red flags. (9) Mentions Deutsche Bank Group affiliation to add credibility. The professional formatting and regulatory references are sophisticated social engineering tactics.",
            recommendations: [
                "Delete this email immediately - it is a phishing scam",
                "Do not click any links or provide personal information",
                "Log into Postbank directly through postbank.de or the official app to check if any action is actually needed",
                "Legitimate 5AMLD compliance is handled within the banking app or through in-branch processes, never via email",
                "Never click links in emails claiming to require identity verification",
                "If you clicked the link and entered information, contact Postbank immediately through official channels",
                "Change your Postbank password if you provided credentials",
                "Monitor your accounts for unauthorized transactions",
                "Report this phishing attempt to Postbank and your email provider",
                "Be aware that scammers frequently exploit legitimate regulations (GDPR, PSD2, 5AMLD) to appear credible"
            ]
        }
    },

    // Email 21 - German MEDIUM TP - Google Foreign Login Alert
    {
        id: 21,
        subject: "Neue Anmeldung von unbekanntem Gerät",
        from: "no-reply@google-security.com",
        language: "de",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Hallo,

Wir haben eine Anmeldung in Ihrem Google-Konto von einem Gerät festgestellt, das wir nicht erkennen.

Anmeldedetails:
Gerät: Samsung Galaxy S24
Standort: Lagos, Nigeria
Zeit: 10. Februar 2026, 03:17 Uhr
Browser: Chrome Mobile 121
IP-Adresse: 197.210.xxx.xxx

War das Sie?

Falls nicht, wurde Ihr Konto möglicherweise kompromittiert.

SOFORT HANDELN:
1. Sichern Sie Ihr Konto: http://google-account-security.com/check
2. Ändern Sie Ihr Passwort
3. Überprüfen Sie kürzliche Aktivitäten
4. Aktivieren Sie 2-Faktor-Authentifizierung

Wenn Sie nicht innerhalb von 12 Stunden reagieren, gehen wir davon aus, dass diese Anmeldung autorisiert war.

Mögliche Risiken:
• Zugriff auf Ihre E-Mails
• Zugriff auf Google Drive-Dateien
• Änderung Ihrer Kontoinformationen
• Nutzung Ihrer Zahlungsmethoden

Schützen Sie Ihre Daten jetzt!

Diese E-Mail wurde automatisch gesendet.

Google LLC
1600 Amphitheatre Parkway
Mountain View, CA 94043, USA`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 74,
                patterns: [
                    "Urgency keyword: unbekanntem Gerät",
                    "Urgency keyword: SOFORT HANDELN",
                    "Urgency keyword: kompromittiert",
                    "Urgency keyword: 12 Stunden",
                    "Suspicious URL detected",
                    "Foreign location (Nigeria)"
                ],
                evidence: [
                    "Unknown device login creates concern",
                    "Foreign location (Lagos, Nigeria) increases fear",
                    "12-hour deadline creates pressure",
                    "Early morning timestamp (03:17) appears suspicious",
                    "Domain google-security.com is suspicious",
                    "Lists multiple risks to increase fear"
                ]
            },
            owasp: {
                score: 68,
                patterns: [
                    "Suspicious URL structure",
                    "Credential harvesting attempt"
                ],
                evidence: [
                    "Non-Google domain (google-account-security.com)",
                    "URL designed to collect Google credentials",
                    "HTTP instead of HTTPS for account security"
                ]
            },
            nist: {
                score: 79,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Google uses google.com",
                    "google-security.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 71,
                patterns: [
                    "Account security action via email link",
                    "Password change through email"
                ],
                evidence: [
                    "Requests security action via email link",
                    "Google handles security through official website/app",
                    "Violates security notification procedures"
                ]
            },
            nessus: {
                score: 66,
                patterns: [
                    "Google security alert scam",
                    "Foreign login theme"
                ],
                evidence: [
                    "Matches known Google phishing campaigns",
                    "Foreign login alert is common tactic",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 70,
                patterns: [
                    "Foreign location fear manipulation",
                    "Account compromise threat",
                    "Data access risk exploitation"
                ],
                evidence: [
                    "Nigeria location creates fear (common scam origin)",
                    "Early morning timestamp appears suspicious",
                    "Lists multiple risks (email, Drive, payment methods)",
                    "12-hour deadline creates urgency",
                    "Exploits fear of identity theft"
                ]
            }
        },
        ollama: {
            summary: "This is a medium-risk phishing email impersonating Google security alerts. It uses fake foreign login attempts from Nigeria to create fear and urgency, tricking recipients into clicking a malicious link and providing their Google account credentials.",
            reasoning: "Multiple indicators suggest phishing: (1) Complete authentication failure - all checks failed, indicating sender spoofing. (2) Domain spoofing - google-security.com and google-account-security.com are NOT official Google domains (official is google.com). (3) Foreign location exploitation - Lagos, Nigeria is used to create fear (commonly associated with scams). (4) Urgency - 12-hour deadline and immediate action request. (5) Early morning timestamp (03:17) appears suspicious. (6) Framework scores in 66-79% range indicate medium-high risk. (7) Google sends legitimate security alerts, but only through the official Google account system, never with external security links. (8) Lists multiple risks (email access, Drive files, payment methods) to increase fear. The email is well-crafted and mimics Google's security alert format, making it more convincing.",
            recommendations: [
                "Delete this email - it is a phishing scam",
                "Do not click any links or provide your Google credentials",
                "Check actual account activity by visiting myaccount.google.com directly",
                "Google sends security alerts through the official account system, not via external links",
                "If you have concerns, review your account activity at myaccount.google.com/security",
                "If you clicked the link and entered credentials, change your Google password immediately",
                "Enable two-factor authentication for additional security",
                "Review connected devices and sign out suspicious sessions",
                "Report this phishing attempt to Google",
                "Be aware that foreign location alerts (especially Nigeria, Russia, China) are common phishing tactics designed to create fear"
            ]
        }
    },

    // Email 22 - German LOW TN - Booking.com Confirmation
    {
        id: 22,
        subject: "Buchungsbestätigung - Hotel Adlon Berlin",
        from: "noreply@booking.com",
        language: "de",
        riskLevel: "LOW",
        classification: "TN",
        body: `Guten Tag Max Mustermann,

Vielen Dank für Ihre Buchung über Booking.com!

Buchungsdetails:
Buchungsnummer: 2847-9302-8475
Buchungsdatum: 10. Februar 2026

Unterkunft:
Hotel Adlon Kempinski Berlin
Unter den Linden 77
10117 Berlin, Deutschland

Check-in: 15. März 2026 (ab 15:00 Uhr)
Check-out: 18. März 2026 (bis 11:00 Uhr)
Aufenthaltsdauer: 3 Nächte

Zimmer:
1x Deluxe Doppelzimmer mit Brandenburger Tor Blick

Gäste: 2 Erwachsene

Preis:
Zimmerpreis: 1.497,00 EUR
Steuern und Gebühren: 178,00 EUR
Gesamtpreis: 1.675,00 EUR

Zahlung: Bei Ankunft im Hotel

Stornierungsbedingungen:
Kostenlose Stornierung bis 13. März 2026, 18:00 Uhr
Danach: 100% des Gesamtpreises

Ihre Buchung verwalten:
www.booking.com/mybooking?bookingid=2847-9302-8475

Kontakt zur Unterkunft:
Telefon: +49 30 22610
E-Mail: info@hotel-adlon.de

Bei Fragen zu Ihrer Buchung:
Booking.com Kundenservice: 24/7 verfügbar
www.booking.com/help

Wir wünschen Ihnen einen angenehmen Aufenthalt!

Mit freundlichen Grüßen,
Das Booking.com Team

Booking.com B.V.
Herengracht 597
1017 CE Amsterdam
Niederlande`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 14,
                patterns: [],
                evidence: [
                    "No urgency keywords",
                    "Standard booking confirmation format",
                    "Professional hospitality language",
                    "Complete booking details provided",
                    "No suspicious requests"
                ]
            },
            owasp: {
                score: 10,
                patterns: [],
                evidence: [
                    "All URLs point to official booking.com domain",
                    "No suspicious links",
                    "Standard confirmation format",
                    "Proper booking management link"
                ]
            },
            nist: {
                score: 8,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain matches Booking.com",
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 12,
                patterns: [],
                evidence: [
                    "No sensitive data requests",
                    "Standard booking communication",
                    "Provides proper contact information",
                    "Appropriate data handling"
                ]
            },
            nessus: {
                score: 9,
                patterns: [],
                evidence: [
                    "No malware signatures",
                    "No exploit attempts",
                    "Clean booking confirmation"
                ]
            },
            openvas: {
                score: 11,
                patterns: [],
                evidence: [
                    "No vulnerability indicators",
                    "Legitimate travel booking confirmation",
                    "Standard hospitality industry format"
                ]
            }
        },
        ollama: {
            summary: "This is a legitimate booking confirmation email from Booking.com for a hotel reservation at Hotel Adlon Kempinski Berlin. All authentication checks passed perfectly, and the email follows standard booking confirmation practices.",
            reasoning: "All indicators confirm legitimacy: (1) Perfect authentication - DMARC, SPF, and DKIM all passed, confirming the email genuinely came from Booking.com servers. (2) Official domain - noreply@booking.com is the correct domain for Booking.com confirmations. (3) Standard format - includes complete booking details (confirmation number, dates, hotel information, pricing, cancellation policy). (4) All links point to official booking.com domain. (5) Professional hospitality language and structure. (6) Provides legitimate hotel contact information. (7) All frameworks scored very low (8-14%) indicating minimal risk. (8) No urgency tactics, no payment requests (payment at hotel), no suspicious elements. (9) Cancellation policy is clearly stated. (10) The hotel (Adlon Kempinski) is a real, prestigious hotel in Berlin.",
            recommendations: [
                "Safe to read - this is a legitimate booking confirmation",
                "Keep this email for your travel records and hotel check-in",
                "Note the check-in time (15:00) and check-out time (11:00)",
                "Review the cancellation policy (free until 13. März, 18:00)",
                "You can manage your booking through the provided link at booking.com",
                "Contact the hotel directly if you have special requests",
                "Save the booking number (2847-9302-8475) for reference",
                "No security action required"
            ]
        }
    },

    // Email 23 - German HIGH TP - Fake Tax Refund
    {
        id: 23,
        subject: "Finanzamt: Steuerrückerstattung von 847,32 EUR",
        from: "service@finanzamt-online.de",
        language: "de",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Sehr geehrte/r Steuerpflichtige/r,

Nach Prüfung Ihrer Steuererklärung für das Jahr 2025 haben wir festgestellt, dass Sie Anspruch auf eine Steuerrückerstattung haben.

Rückerstattungsbetrag: 847,32 EUR
Steuernummer: 12/345/67890
Veranlagungsjahr: 2025

Grund der Rückerstattung:
• Zu viel gezahlte Lohnsteuer: 623,45 EUR
• Werbungskosten: 156,87 EUR
• Sonderausgaben: 67,00 EUR

Um Ihre Rückerstattung zu erhalten, müssen Sie Ihre Bankverbindung bestätigen.

Jetzt Bankdaten bestätigen: http://finanzamt-rueckerstattung.de/verify?tn=12345

WICHTIG: Bestätigung bis 15. Februar 2026 erforderlich!

Nach Ablauf der Frist verfällt Ihr Anspruch auf die Rückerstattung.

Benötigte Informationen:
• IBAN
• BIC
• Kontoinhaber
• Geburtsdatum (zur Verifizierung)

Die Überweisung erfolgt innerhalb von 3-5 Werktagen nach Bestätigung.

Hinweis: Dies ist eine automatisch generierte E-Mail des Bundeszentralamts für Steuern.

Mit freundlichen Grüßen,
Finanzamt für Körperschaften I Berlin

Bundeszentralamt für Steuern
An der Küppe 1
53225 Bonn`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 88,
                patterns: [
                    "Urgency keyword: WICHTIG",
                    "Urgency keyword: verfällt",
                    "Deadline mentioned (15. Februar)",
                    "Suspicious URL detected",
                    "Financial reward (tax refund)",
                    "Bank details request"
                ],
                evidence: [
                    "Tax refund creates positive incentive",
                    "Specific amount (847,32 EUR) appears legitimate",
                    "Deadline creates urgency",
                    "Domain finanzamt-online.de is suspicious",
                    "Requests sensitive banking information",
                    "Threatens loss of refund"
                ]
            },
            owasp: {
                score: 82,
                patterns: [
                    "Banking information harvesting",
                    "Identity theft attempt",
                    "Suspicious verification URL"
                ],
                evidence: [
                    "Non-Finanzamt domain with verification path",
                    "URL designed to collect banking details",
                    "Requests IBAN, BIC, and personal information",
                    "HTTP instead of HTTPS for financial data"
                ]
            },
            nist: {
                score: 90,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Government domain spoofing"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Finanzamt uses finanzamt.de or elster.de",
                    "finanzamt-online.de is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 86,
                patterns: [
                    "Banking information request via email",
                    "Personal data collection through email link",
                    "Government impersonation"
                ],
                evidence: [
                    "Requests IBAN, BIC, and birth date via email",
                    "German tax authorities use ELSTER system, not email links",
                    "Violates government data security protocols",
                    "Legitimate refunds processed through official tax portal"
                ]
            },
            nessus: {
                score: 84,
                patterns: [
                    "Tax refund scam pattern",
                    "Government impersonation detected"
                ],
                evidence: [
                    "Matches known tax refund phishing campaigns",
                    "Finanzamt impersonation is common",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 85,
                patterns: [
                    "Financial reward manipulation",
                    "Authority exploitation (government)",
                    "Deadline pressure with loss threat"
                ],
                evidence: [
                    "Uses financial reward to motivate action",
                    "Specific refund amount appears legitimate",
                    "Exploits government authority for trust",
                    "Threatens loss of refund to create urgency",
                    "Detailed breakdown adds credibility"
                ]
            }
        },
        ollama: {
            summary: "This is a high-confidence phishing email impersonating the German tax authority (Finanzamt). It uses fake tax refund notifications to trick recipients into providing banking information and personal data, leading to identity theft and potential bank account fraud.",
            reasoning: "Critical phishing indicators across all frameworks: (1) Complete authentication failure - all checks failed, confirming sender spoofing. (2) Domain spoofing - finanzamt-online.de and finanzamt-rueckerstattung.de are NOT official tax authority domains (official is finanzamt.de or elster.de). (3) Banking information request - asks for IBAN, BIC, account holder name, and birth date via email link, which legitimate tax authorities never do. (4) Process violation - German tax refunds are processed exclusively through the ELSTER system or by mail, never via email links. (5) Urgency - deadline with threat of losing refund. (6) All frameworks scored 82%+ indicating unanimous high-risk assessment. (7) Financial reward tactic - uses positive incentive (refund) instead of threats, making it more appealing. (8) Specific details (exact amount, tax number, breakdown) are designed to appear legitimate. The professional formatting and official-sounding language exploit trust in government institutions.",
            recommendations: [
                "Delete this email immediately - it is a phishing scam",
                "Do not click any links or provide banking information",
                "The German tax authority (Finanzamt) never requests banking details via email",
                "Tax refunds are processed through the official ELSTER system (elster.de) or sent by mail",
                "Check your actual tax status by logging into elster.de or contacting your local Finanzamt",
                "If you clicked the link and entered information, contact your bank immediately",
                "Monitor your bank account for unauthorized transactions",
                "Report this scam to the Bundeszentralamt für Steuern",
                "Be aware that tax refund scams are extremely common, especially during tax season",
                "Legitimate tax communications come via official mail or through the ELSTER portal"
            ]
        }
    },

    // Email 24 - German LOW FN - Legitimate But Suspicious Looking Newsletter
    {
        id: 24,
        subject: "LETZTE CHANCE: 50% Rabatt endet HEUTE!",
        from: "newsletter@zalando.de",
        language: "de",
        riskLevel: "LOW",
        classification: "FN",
        body: `Hallo Max,

⏰ NUR NOCH HEUTE: 50% auf ALLES! ⏰

Deine Lieblingsmarken zum halben Preis:
• Nike - Bis zu 50% Rabatt
• Adidas - Bis zu 50% Rabatt
• Tommy Hilfiger - Bis zu 50% Rabatt
• Levi's - Bis zu 50% Rabatt

JETZT ZUSCHLAGEN: www.zalando.de/sale

Angebot gültig nur bis 23:59 Uhr heute!

🔥 TOP-DEALS:
Sneaker ab 39,99 EUR
Jeans ab 29,99 EUR
Jacken ab 49,99 EUR

Kostenloser Versand + 100 Tage Rückgaberecht!

VERPASSE NICHT DIESE CHANCE!

Zum Shop: www.zalando.de

Abmelden: www.zalando.de/newsletter/abmelden

Zalando SE
Valeska-Gert-Straße 5
10243 Berlin`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 58,
                patterns: [
                    "Urgency keyword: LETZTE CHANCE",
                    "Urgency keyword: endet HEUTE",
                    "Urgency keyword: NUR NOCH HEUTE",
                    "Urgency keyword: JETZT ZUSCHLAGEN",
                    "Urgency keyword: VERPASSE NICHT",
                    "Large discount (50%)",
                    "Multiple urgency indicators"
                ],
                evidence: [
                    "Subject line in all caps creates urgency",
                    "Same-day deadline (23:59 Uhr)",
                    "50% discount on everything seems too good",
                    "Multiple urgency phrases throughout",
                    "However, domain is legitimate zalando.de",
                    "This is aggressive marketing, not phishing"
                ]
            },
            owasp: {
                score: 22,
                patterns: [],
                evidence: [
                    "All URLs point to official zalando.de domain",
                    "No suspicious links",
                    "Standard e-commerce newsletter format",
                    "Proper unsubscribe link included"
                ]
            },
            nist: {
                score: 12,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain matches Zalando",
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 28,
                patterns: [
                    "Aggressive marketing tactics"
                ],
                evidence: [
                    "No sensitive data requests",
                    "Standard marketing communication",
                    "GDPR-compliant unsubscribe option",
                    "However, uses aggressive urgency tactics"
                ]
            },
            nessus: {
                score: 24,
                patterns: [
                    "Aggressive marketing pattern"
                ],
                evidence: [
                    "Marketing tactics resemble phishing urgency",
                    "However, this is legitimate e-commerce",
                    "No malware or exploits"
                ]
            },
            openvas: {
                score: 32,
                patterns: [
                    "FOMO exploitation (Fear of Missing Out)",
                    "Urgency manipulation",
                    "Scarcity tactics"
                ],
                evidence: [
                    "Uses extreme urgency language",
                    "Same-day deadline creates pressure",
                    "50% discount creates FOMO",
                    "However, this is standard retail marketing",
                    "Legitimate but aggressive tactics"
                ]
            }
        },
        ollama: {
            summary: "This is a FALSE NEGATIVE - a legitimate marketing email from Zalando that uses aggressive urgency tactics typically associated with phishing. While authentic, it was flagged due to excessive urgency language and pressure tactics that resemble scam emails.",
            reasoning: "This is classified as a FALSE NEGATIVE because it appears suspicious but is actually legitimate: (1) Perfect authentication - DMARC, SPF, DKIM all passed, confirming it genuinely came from Zalando. (2) Official domain - newsletter@zalando.de is correct for Zalando marketing. (3) All links point to legitimate zalando.de domain. (4) However, ML classifier scored 58% due to extreme urgency language: 'LETZTE CHANCE', 'endet HEUTE', 'NUR NOCH HEUTE', 'JETZT ZUSCHLAGEN', 'VERPASSE NICHT'. (5) 50% discount on everything seems too good to be true. (6) Same-day deadline (23:59 Uhr) creates pressure. (7) All caps subject line and fire emojis are aggressive marketing. (8) This demonstrates that legitimate marketing emails can trigger phishing detection when they use aggressive urgency tactics, scarcity messaging, and FOMO (Fear of Missing Out) strategies. The line between aggressive marketing and phishing tactics has blurred, making it harder to distinguish legitimate promotions from scams.",
            recommendations: [
                "This is a legitimate marketing email from Zalando",
                "The urgency tactics are aggressive marketing, not a scam",
                "If interested in the sale, visit zalando.de directly rather than clicking email links",
                "Verify the sale exists by checking Zalando's website or app independently",
                "Be cautious: legitimate retailers increasingly use phishing-like urgency tactics",
                "Consider unsubscribing if you find these emails too aggressive",
                "Always verify 'too good to be true' offers (50% on everything) independently",
                "Zalando is a legitimate German fashion retailer",
                "This email demonstrates why user education is important: not all urgent emails are scams, but urgency should always trigger verification",
                "Best practice: When in doubt, visit the website directly instead of clicking email links"
            ]
        }
    }
];

    // Email 25 - English HIGH TP - PayPal Account Limitation
    {
        id: 25,
        subject: "Action Required: Your PayPal Account Has Been Limited",
        from: "service@paypal-security.com",
        language: "en",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Dear PayPal Customer,

We have detected unusual activity on your PayPal account and have temporarily limited your account access to protect your funds.

Account Status: LIMITED
Reference Number: PP-2026-8492-7361
Date: February 10, 2026

Detected Issues:
• Multiple failed login attempts from unknown IP addresses
• Unusual transaction pattern detected
• Account information needs verification
• Security questions require update

Affected Services:
✗ Send Money
✗ Receive Money
✗ Withdraw Funds
✗ Make Purchases

IMMEDIATE ACTION REQUIRED:

To restore full account access, please verify your identity:
http://paypal-verify-account.com/restore?ref=PP8492

You must complete verification within 48 hours or your account will be permanently suspended.

Required Information:
• Email address and password
• Credit/debit card information
• Social Security Number (for US customers)
• Government-issued ID

After verification, your account will be restored within 24 hours.

Failure to verify will result in:
• Permanent account suspension
• Funds held for 180 days
• Loss of buyer/seller protection
• Inability to access your money

Protect your account now!

Sincerely,
PayPal Security Team

PayPal, Inc.
2211 North First Street
San Jose, CA 95131, USA

This is an automated security notification.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 94,
                patterns: [
                    "Urgency keyword: Action Required",
                    "Urgency keyword: LIMITED",
                    "Urgency keyword: IMMEDIATE ACTION",
                    "Urgency keyword: 48 hours",
                    "Urgency keyword: permanently suspended",
                    "Suspicious URL detected",
                    "Multiple threat scenarios",
                    "Sensitive data request"
                ],
                evidence: [
                    "Account limitation creates immediate concern",
                    "48-hour deadline creates pressure",
                    "Lists multiple service disruptions",
                    "Threatens permanent suspension and fund holding (180 days)",
                    "Domain paypal-security.com is suspicious",
                    "Requests extremely sensitive information (SSN, ID, card details)",
                    "Multiple failed login attempts create fear"
                ]
            },
            owasp: {
                score: 91,
                patterns: [
                    "Malicious redirect detected",
                    "Credential harvesting attempt",
                    "Identity theft risk",
                    "Financial data collection"
                ],
                evidence: [
                    "Non-PayPal domain with verification path",
                    "URL designed to collect PayPal credentials and financial data",
                    "Requests SSN and government ID - extreme red flag",
                    "Reference parameter suggests tracking",
                    "HTTP instead of HTTPS for financial data"
                ]
            },
            nist: {
                score: 93,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "Complete authentication failure",
                    "Official PayPal uses paypal.com",
                    "paypal-security.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 92,
                patterns: [
                    "Identity verification via email link",
                    "Sensitive data request (SSN, ID)",
                    "Financial information collection",
                    "Security policy violation"
                ],
                evidence: [
                    "Requests SSN and government ID via email - major violation",
                    "Asks for credit card information",
                    "PayPal handles verification through secure in-app processes",
                    "Violates financial security standards",
                    "Legitimate PayPal never requests SSN via email"
                ]
            },
            nessus: {
                score: 90,
                patterns: [
                    "PayPal phishing pattern",
                    "Account limitation scam detected",
                    "Known threat signature"
                ],
                evidence: [
                    "Matches known PayPal phishing campaigns",
                    "Account limitation theme is extremely common",
                    "Similar attacks widely documented",
                    "PayPal is the most impersonated brand in phishing"
                ]
            },
            openvas: {
                score: 91,
                patterns: [
                    "Financial loss fear manipulation",
                    "Multiple service disruption threats",
                    "Fund holding threat (180 days)",
                    "Identity theft attempt"
                ],
                evidence: [
                    "Threatens 180-day fund hold - creates extreme fear",
                    "Lists multiple service disruptions (send, receive, withdraw, purchase)",
                    "Combines multiple fears: account loss, money inaccessibility, protection loss",
                    "Requests identity documents for theft",
                    "48-hour deadline increases panic"
                ]
            }
        },
        ollama: {
            summary: "This is a high-confidence phishing email impersonating PayPal. It uses sophisticated social engineering with fake security alerts and account limitations to panic recipients into providing extremely sensitive information including Social Security Numbers, government IDs, and financial data.",
            reasoning: "Critical phishing indicators across all frameworks: (1) Complete authentication failure - all checks failed, confirming sender spoofing. (2) Domain spoofing - paypal-security.com and paypal-verify-account.com are NOT official PayPal domains (official is paypal.com). (3) Extreme data requests - asking for SSN, government ID, and credit card details via email is a massive red flag that legitimate companies never do. (4) Multiple threats - account suspension, 180-day fund hold, loss of protections, money inaccessibility. (5) Urgent deadline - 48 hours with severe consequences. (6) All frameworks scored 90%+ indicating unanimous critical-risk assessment. (7) PayPal handles all account security through the official website or app, never via email links requesting sensitive data. (8) The professional formatting with reference numbers and legal address is designed to appear legitimate. (9) PayPal is the most impersonated brand in phishing attacks due to its financial nature. This email could lead to complete identity theft and financial fraud if victims provide the requested information.",
            recommendations: [
                "Delete this email immediately - it is a dangerous phishing scam",
                "Do not click any links or provide any information",
                "NEVER provide SSN, government ID, or credit card details via email",
                "Check your actual PayPal account status by visiting paypal.com directly",
                "PayPal never requests sensitive information via email",
                "If you clicked the link and entered information, take immediate action: (1) Change your PayPal password at paypal.com, (2) Contact PayPal security immediately, (3) Contact your bank if you provided financial information, (4) Monitor your credit report for identity theft, (5) Consider placing a fraud alert with credit bureaus",
                "Enable two-factor authentication on your PayPal account",
                "Report this phishing attempt to phishing@paypal.com",
                "Be aware that PayPal phishing is extremely common - always verify account issues by logging in directly",
                "Legitimate PayPal communications about account issues direct you to resolve them within the PayPal app or website, never via email links"
            ]
        }
    },

    // Email 26 - English MEDIUM TP - Amazon Unusual Login Activity
    {
        id: 26,
        subject: "Amazon: Unusual sign-in activity detected",
        from: "account-update@amazon-security.com",
        language: "en",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Hello,

We noticed a new sign-in to your Amazon account from a device we don't recognize.

Sign-in Details:
Device: Windows PC
Location: Shanghai, China
Time: February 10, 2026 at 4:23 AM EST
Browser: Firefox 122
IP Address: 218.76.xxx.xxx

Was this you?

If you don't recognize this activity, your account may have been compromised.

SECURE YOUR ACCOUNT NOW:
http://amazon-account-security.com/verify?session=AMZ2026

Recommended Actions:
1. Verify your identity
2. Change your password
3. Review recent orders
4. Update security settings

If you don't respond within 24 hours, we'll assume this sign-in was authorized.

Potential Risks:
• Unauthorized purchases
• Access to payment methods
• Viewing of order history
• Changes to account settings
• Use of stored gift card balances

Your account security is our priority.

This is an automated message from Amazon Security.

Amazon.com, Inc.
410 Terry Avenue North
Seattle, WA 98109, USA`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 71,
                patterns: [
                    "Urgency keyword: Unusual activity",
                    "Urgency keyword: compromised",
                    "Urgency keyword: SECURE YOUR ACCOUNT",
                    "Urgency keyword: 24 hours",
                    "Suspicious URL detected",
                    "Foreign location (China)"
                ],
                evidence: [
                    "Unknown device login creates concern",
                    "Foreign location (Shanghai, China) increases fear",
                    "24-hour deadline creates pressure",
                    "Early morning timestamp (4:23 AM) appears suspicious",
                    "Domain amazon-security.com is suspicious",
                    "Lists multiple risks to increase fear"
                ]
            },
            owasp: {
                score: 66,
                patterns: [
                    "Suspicious URL structure",
                    "Credential harvesting attempt",
                    "Session tracking parameter"
                ],
                evidence: [
                    "Non-Amazon domain (amazon-account-security.com)",
                    "URL designed to collect Amazon credentials",
                    "Session parameter suggests tracking",
                    "HTTP instead of HTTPS for account security"
                ]
            },
            nist: {
                score: 76,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Amazon uses amazon.com",
                    "amazon-security.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 69,
                patterns: [
                    "Account security action via email link",
                    "Identity verification through email"
                ],
                evidence: [
                    "Requests security action via email link",
                    "Amazon handles security through official website/app",
                    "Violates security notification procedures"
                ]
            },
            nessus: {
                score: 64,
                patterns: [
                    "Amazon security alert scam",
                    "Foreign login theme"
                ],
                evidence: [
                    "Matches known Amazon phishing campaigns",
                    "Foreign login alert is common tactic",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 68,
                patterns: [
                    "Foreign location fear manipulation",
                    "Account compromise threat",
                    "Financial risk exploitation"
                ],
                evidence: [
                    "China location creates fear (common scam origin)",
                    "Early morning timestamp appears suspicious",
                    "Lists multiple risks (purchases, payment methods, gift cards)",
                    "24-hour deadline creates urgency",
                    "Exploits fear of unauthorized purchases"
                ]
            }
        },
        ollama: {
            summary: "This is a medium-risk phishing email impersonating Amazon security alerts. It uses fake foreign login attempts from China to create fear and urgency, tricking recipients into clicking a malicious link and providing their Amazon account credentials.",
            reasoning: "Multiple indicators suggest phishing: (1) Complete authentication failure - all checks failed, indicating sender spoofing. (2) Domain spoofing - amazon-security.com and amazon-account-security.com are NOT official Amazon domains (official is amazon.com). (3) Foreign location exploitation - Shanghai, China is used to create fear (commonly associated with cyber threats). (4) Urgency - 24-hour deadline and immediate action request. (5) Early morning timestamp (4:23 AM EST) appears suspicious. (6) Framework scores in 64-76% range indicate medium-high risk. (7) Amazon sends legitimate security alerts, but only through the official Amazon website or app, never with external security links. (8) Lists multiple risks (purchases, payment methods, gift cards) to increase fear. The email is well-crafted and mimics Amazon's security alert format, making it more convincing than obvious scams.",
            recommendations: [
                "Delete this email - it is a phishing scam",
                "Do not click any links or provide your Amazon credentials",
                "Check actual account activity by visiting amazon.com directly",
                "Amazon sends security alerts through the official account system, not via external links",
                "If you have concerns, review your account activity at amazon.com/youraccount",
                "If you clicked the link and entered credentials, change your Amazon password immediately at amazon.com",
                "Enable two-factor authentication for additional security",
                "Review connected devices and sign out suspicious sessions",
                "Report this phishing attempt to Amazon at stop-spoofing@amazon.com",
                "Be aware that foreign location alerts (especially China, Russia, Nigeria) are common phishing tactics designed to create fear"
            ]
        }
    },

    // Email 27 - English LOW TN - UPS Delivery Notification
    {
        id: 27,
        subject: "UPS Delivery Alert: Package arriving today",
        from: "pkginfo@ups.com",
        language: "en",
        riskLevel: "LOW",
        classification: "TN",
        body: `Hello,

Your package is out for delivery and will arrive today.

Tracking Number: 1Z999AA10123456784
Shipper: Apple Inc.
Recipient: Max Mustermann

Current Status: Out for Delivery
Estimated Delivery: Today, February 10, 2026 by 8:00 PM

Shipment Progress:
Feb 09, 2026 7:15 PM - Departed from facility in Louisville, KY
Feb 10, 2026 5:30 AM - Arrived at facility in New York, NY
Feb 10, 2026 8:45 AM - Out for delivery

Your package will be delivered today between 9:00 AM and 8:00 PM.

Track your package:
www.ups.com/track?tracknum=1Z999AA10123456784

Delivery Options:
• Authorize shipment release (no signature required)
• Redirect to a UPS Access Point
• Reschedule delivery
• Hold for pickup at UPS facility

Manage delivery: www.ups.com/mychoice

Questions?
UPS Customer Service: 1-800-742-5877
Online Support: www.ups.com/help

Thank you for choosing UPS.

United Parcel Service of America, Inc.
55 Glenlake Parkway, NE
Atlanta, GA 30328, USA`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 15,
                patterns: [],
                evidence: [
                    "No urgency keywords",
                    "Standard delivery notification format",
                    "Professional logistics language",
                    "Provides tracking history",
                    "No suspicious requests"
                ]
            },
            owasp: {
                score: 10,
                patterns: [],
                evidence: [
                    "All URLs point to official ups.com domain",
                    "No suspicious links",
                    "Standard tracking format",
                    "Proper delivery management options"
                ]
            },
            nist: {
                score: 8,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain matches UPS",
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 12,
                patterns: [],
                evidence: [
                    "No sensitive data requests",
                    "Standard delivery communication",
                    "Provides legitimate delivery options",
                    "Appropriate contact information"
                ]
            },
            nessus: {
                score: 9,
                patterns: [],
                evidence: [
                    "No malware signatures",
                    "No exploit attempts",
                    "Clean delivery notification"
                ]
            },
            openvas: {
                score: 11,
                patterns: [],
                evidence: [
                    "No vulnerability indicators",
                    "Legitimate courier service communication",
                    "Standard tracking update format"
                ]
            }
        },
        ollama: {
            summary: "This is a legitimate package delivery notification from UPS. All authentication checks passed perfectly, and the email follows standard delivery notification practices with proper tracking information and official links.",
            reasoning: "All indicators confirm legitimacy: (1) Perfect authentication - DMARC, SPF, and DKIM all passed, confirming the email genuinely came from UPS servers. (2) Official domain - pkginfo@ups.com is the correct domain for UPS tracking notifications. (3) Standard format - includes proper tracking number, shipper/recipient information, delivery timeline, and shipment progress. (4) All links point to official ups.com domain. (5) Professional logistics language and structure. (6) Provides helpful delivery options (signature release, redirect, reschedule, hold for pickup). (7) Complete contact information with official customer service number. (8) All frameworks scored very low (8-15%) indicating minimal risk. (9) No urgency tactics, no payment requests, no suspicious elements. (10) Tracking number format matches UPS standards (1Z format).",
            recommendations: [
                "Safe to read - this is a legitimate delivery notification",
                "Your package from Apple Inc. is scheduled for delivery today by 8:00 PM",
                "Use the tracking link to monitor real-time delivery status",
                "Consider setting up delivery options if you won't be home",
                "Keep this email for reference if delivery issues arise",
                "The tracking number can be used on the UPS website or app",
                "No security action required"
            ]
        }
    },

    // Email 28 - English HIGH TP - Microsoft 365 Subscription Expiration
    {
        id: 28,
        subject: "URGENT: Your Microsoft 365 subscription expires today",
        from: "billing@microsoft-office.com",
        language: "en",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Dear Microsoft Customer,

Your Microsoft 365 subscription is expiring today and requires immediate renewal.

Account: max.mustermann@email.com
Subscription: Microsoft 365 Family
Expiration Date: February 10, 2026
Status: EXPIRING TODAY

IMMEDIATE ACTION REQUIRED

If you don't renew today, you will lose access to:
✗ Microsoft Word, Excel, PowerPoint
✗ Outlook email service
✗ OneDrive cloud storage (1TB)
✗ Microsoft Teams
✗ All your stored documents and files

RENEW NOW: http://microsoft-renewal.com/subscribe?id=M365-2026

Special Offer - Renew Today:
Regular Price: $99.99/year
Today Only: $79.99/year
SAVE $20!

This offer expires at midnight tonight!

After expiration:
• Your files will be deleted after 30 days
• Email access will be terminated
• You'll lose all OneDrive data
• Office applications will stop working

To continue using Microsoft 365, renew your subscription now.

Payment methods accepted:
• Credit/Debit Card
• PayPal
• Bank Transfer

Secure your data and productivity today!

Microsoft Corporation
One Microsoft Way
Redmond, WA 98052, USA

This is an automated billing notification.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 92,
                patterns: [
                    "Urgency keyword: URGENT",
                    "Urgency keyword: expires today",
                    "Urgency keyword: EXPIRING TODAY",
                    "Urgency keyword: IMMEDIATE ACTION",
                    "Urgency keyword: midnight tonight",
                    "Suspicious URL detected",
                    "Multiple threat scenarios",
                    "Limited-time discount"
                ],
                evidence: [
                    "Subscription expiration creates immediate concern",
                    "Same-day deadline creates extreme pressure",
                    "Lists multiple service disruptions",
                    "Threatens data deletion (30 days)",
                    "Domain microsoft-office.com is suspicious",
                    "Limited-time discount (save $20) adds urgency",
                    "Midnight deadline increases panic"
                ]
            },
            owasp: {
                score: 86,
                patterns: [
                    "Malicious redirect detected",
                    "Payment information harvesting",
                    "Credential collection attempt"
                ],
                evidence: [
                    "Non-Microsoft domain with subscription path",
                    "URL designed to collect payment information",
                    "ID parameter suggests tracking",
                    "HTTP instead of HTTPS for payment processing"
                ]
            },
            nist: {
                score: 90,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "Complete authentication failure",
                    "Official Microsoft uses microsoft.com",
                    "microsoft-office.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 88,
                patterns: [
                    "Payment request via email link",
                    "Subscription renewal through email",
                    "Security policy violation"
                ],
                evidence: [
                    "Requests payment via email link",
                    "Microsoft handles subscriptions through official account portal",
                    "Violates payment security practices",
                    "Legitimate renewals processed through account.microsoft.com"
                ]
            },
            nessus: {
                score: 84,
                patterns: [
                    "Microsoft subscription scam",
                    "Office 365 phishing pattern"
                ],
                evidence: [
                    "Matches known Microsoft phishing campaigns",
                    "Subscription expiration theme is common",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 87,
                patterns: [
                    "Data loss fear manipulation",
                    "Service disruption threats",
                    "File deletion threat",
                    "Productivity loss exploitation"
                ],
                evidence: [
                    "Threatens deletion of OneDrive files after 30 days",
                    "Lists multiple service disruptions (Office apps, email, cloud storage, Teams)",
                    "Exploits fear of losing work documents",
                    "Same-day deadline with midnight expiration",
                    "Discount offer creates additional urgency"
                ]
            }
        },
        ollama: {
            summary: "This is a high-confidence phishing email impersonating Microsoft. It uses fake subscription expiration notifications with same-day deadlines and data deletion threats to panic recipients into clicking a malicious link and providing payment information.",
            reasoning: "Critical phishing indicators across all frameworks: (1) Complete authentication failure - all checks failed, confirming sender spoofing. (2) Domain spoofing - microsoft-office.com and microsoft-renewal.com are NOT official Microsoft domains (official is microsoft.com). (3) Multiple threats - loss of Office apps, email termination, OneDrive data deletion, Teams access loss. (4) Extreme urgency - same-day expiration with midnight deadline. (5) Data loss threat - 30-day deletion warning creates fear of losing important documents. (6) All frameworks scored 84%+ indicating unanimous high-risk assessment. (7) Microsoft handles all subscription renewals through account.microsoft.com or the Microsoft Store, never via email links. (8) The discount offer (save $20) adds urgency and makes the scam more appealing. (9) Professional formatting with product list and legal address is designed to appear legitimate. This email could lead to payment fraud and potential account compromise if victims provide their Microsoft credentials.",
            recommendations: [
                "Delete this email immediately - it is a phishing scam",
                "Do not click any links or provide payment information",
                "Check your actual Microsoft 365 subscription status at account.microsoft.com",
                "Microsoft sends renewal reminders through the official account portal, not via email payment links",
                "If you clicked the link and entered information, take immediate action: (1) Change your Microsoft account password at account.microsoft.com, (2) Contact Microsoft support, (3) Contact your bank if you provided payment information",
                "Enable two-factor authentication on your Microsoft account",
                "Review your subscription and payment settings at account.microsoft.com/services",
                "Report this phishing attempt to Microsoft at reportabuse@microsoft.com",
                "Be aware that Microsoft 365 subscription scams are common due to the widespread use of Office products",
                "Legitimate Microsoft communications direct you to manage subscriptions within your account portal, never via email payment links"
            ]
        }
    },

    // Email 29 - English LOW FP - Aggressive Marketing Email Flagged as Suspicious
    {
        id: 29,
        subject: "LAST CHANCE: Your exclusive 70% discount expires in 3 hours!",
        from: "deals@bestbuy.com",
        language: "en",
        riskLevel: "LOW",
        classification: "FP",
        body: `Hi Max,

🔥 FINAL HOURS: 70% OFF EVERYTHING! 🔥

This is your LAST CHANCE to save big!

EXCLUSIVE DEALS ENDING SOON:
• 4K TVs - Starting at $299
• Laptops - Starting at $399
• Gaming Consoles - Starting at $199
• Smartphones - Starting at $249

SHOP NOW: www.bestbuy.com/deals

⏰ OFFER EXPIRES IN 3 HOURS! ⏰

Don't miss out on these incredible savings!

FREE SHIPPING + FREE RETURNS

This is a limited-time offer for valued customers only.

Shop now: www.bestbuy.com

Unsubscribe: www.bestbuy.com/unsubscribe

Best Buy Co., Inc.
7601 Penn Avenue South
Richfield, MN 55423, USA`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 62,
                patterns: [
                    "Urgency keyword: LAST CHANCE",
                    "Urgency keyword: expires in 3 hours",
                    "Urgency keyword: FINAL HOURS",
                    "Urgency keyword: ENDING SOON",
                    "Urgency keyword: Don't miss out",
                    "Large discount (70%)",
                    "Multiple urgency indicators"
                ],
                evidence: [
                    "Subject line in all caps creates urgency",
                    "3-hour deadline creates extreme pressure",
                    "70% discount seems too good to be true",
                    "Multiple urgency phrases throughout",
                    "Fire emojis and alarm clock emoji add pressure",
                    "However, domain is legitimate bestbuy.com",
                    "This is aggressive marketing, not phishing"
                ]
            },
            owasp: {
                score: 18,
                patterns: [],
                evidence: [
                    "All URLs point to official bestbuy.com domain",
                    "No suspicious links",
                    "Standard e-commerce newsletter format",
                    "Proper unsubscribe link included"
                ]
            },
            nist: {
                score: 9,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain matches Best Buy",
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 24,
                patterns: [
                    "Aggressive marketing tactics"
                ],
                evidence: [
                    "No sensitive data requests",
                    "Standard marketing communication",
                    "GDPR-compliant unsubscribe option",
                    "However, uses aggressive urgency tactics"
                ]
            },
            nessus: {
                score: 21,
                patterns: [
                    "Aggressive marketing pattern"
                ],
                evidence: [
                    "Marketing tactics resemble phishing urgency",
                    "However, this is legitimate e-commerce",
                    "No malware or exploits"
                ]
            },
            openvas: {
                score: 28,
                patterns: [
                    "FOMO exploitation (Fear of Missing Out)",
                    "Urgency manipulation",
                    "Scarcity tactics"
                ],
                evidence: [
                    "Uses extreme urgency language",
                    "3-hour deadline creates pressure",
                    "70% discount creates FOMO",
                    "However, this is standard retail marketing",
                    "Legitimate but aggressive tactics"
                ]
            }
        },
        ollama: {
            summary: "This is a FALSE POSITIVE - a legitimate marketing email from Best Buy that was flagged due to aggressive urgency tactics typically associated with phishing. While authentic, the ML classifier scored it at 62% due to excessive urgency language and pressure tactics.",
            reasoning: "This is classified as a FALSE POSITIVE because it appears suspicious but is actually legitimate: (1) Perfect authentication - DMARC, SPF, DKIM all passed, confirming it genuinely came from Best Buy. (2) Official domain - deals@bestbuy.com is correct for Best Buy marketing. (3) All links point to legitimate bestbuy.com domain. (4) However, ML classifier scored 62% due to extreme urgency language: 'LAST CHANCE', 'expires in 3 hours', 'FINAL HOURS', 'ENDING SOON', 'Don't miss out'. (5) 70% discount on everything seems too good to be true. (6) 3-hour deadline creates extreme pressure. (7) All caps subject line and fire/alarm emojis are aggressive marketing. (8) This demonstrates that legitimate marketing emails can trigger phishing detection when they use aggressive urgency tactics, scarcity messaging, and FOMO (Fear of Missing Out) strategies. (9) The line between aggressive marketing and phishing tactics has blurred, making it harder to distinguish legitimate promotions from scams. (10) Best Buy is a legitimate major electronics retailer in the US.",
            recommendations: [
                "This is a legitimate marketing email from Best Buy",
                "The urgency tactics are aggressive marketing, not a scam",
                "If interested in the deals, visit bestbuy.com directly rather than clicking email links",
                "Verify the sale exists by checking Best Buy's website independently",
                "Be cautious: legitimate retailers increasingly use phishing-like urgency tactics",
                "Consider unsubscribing if you find these emails too aggressive",
                "Always verify 'too good to be true' offers (70% off everything) independently",
                "Best Buy is a legitimate major US electronics retailer",
                "This email demonstrates why user education is important: not all urgent emails are scams, but urgency should always trigger verification",
                "Best practice: When in doubt, visit the website directly instead of clicking email links"
            ]
        }
    },

    // Email 30 - English MEDIUM TP - Apple ID Account Lock
    {
        id: 30,
        subject: "Your Apple ID has been locked for security reasons",
        from: "appleid@apple-support.com",
        language: "en",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Dear Apple Customer,

We have detected suspicious activity on your Apple ID and have temporarily locked your account to protect your information.

Apple ID: max.mustermann@email.com
Lock Date: February 10, 2026
Reason: Multiple failed password attempts

Detected Issues:
• 5 failed login attempts from unknown device
• Location: Moscow, Russia
• Device: Unknown Windows PC
• Time: 2:45 AM EST

Your account has been locked to prevent unauthorized access.

UNLOCK YOUR ACCOUNT:
http://appleid-unlock.com/verify?case=APL2026

You must verify your identity within 24 hours or your account will be permanently disabled.

Affected Services:
• iCloud
• App Store
• Apple Music
• iMessage and FaceTime
• Find My iPhone

After 24 hours without verification:
• All iCloud data will be deleted
• Purchased apps and media will be lost
• Your devices will be remotely locked

Verify your identity now to restore access.

Apple Inc.
One Apple Park Way
Cupertino, CA 95014, USA

This is an automated security message.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 78,
                patterns: [
                    "Urgency keyword: locked",
                    "Urgency keyword: suspicious activity",
                    "Urgency keyword: 24 hours",
                    "Urgency keyword: permanently disabled",
                    "Urgency keyword: deleted",
                    "Suspicious URL detected",
                    "Foreign location (Russia)"
                ],
                evidence: [
                    "Account lock creates immediate concern",
                    "24-hour deadline creates pressure",
                    "Foreign location (Moscow, Russia) increases fear",
                    "Early morning timestamp (2:45 AM) appears suspicious",
                    "Domain apple-support.com is suspicious",
                    "Threatens data deletion and device lock",
                    "Lists multiple service disruptions"
                ]
            },
            owasp: {
                score: 72,
                patterns: [
                    "Suspicious URL structure",
                    "Credential harvesting attempt",
                    "Case tracking parameter"
                ],
                evidence: [
                    "Non-Apple domain (appleid-unlock.com)",
                    "URL designed to collect Apple ID credentials",
                    "Case parameter suggests tracking",
                    "HTTP instead of HTTPS for account security"
                ]
            },
            nist: {
                score: 81,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Apple uses apple.com or icloud.com",
                    "apple-support.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 75,
                patterns: [
                    "Account unlock via email link",
                    "Identity verification through email"
                ],
                evidence: [
                    "Requests identity verification via email",
                    "Apple handles security through official website/app",
                    "Violates security notification procedures"
                ]
            },
            nessus: {
                score: 70,
                patterns: [
                    "Apple ID phishing pattern",
                    "Account lock scam"
                ],
                evidence: [
                    "Matches known Apple phishing campaigns",
                    "Account lock theme is common",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 74,
                patterns: [
                    "Foreign location fear manipulation",
                    "Data loss threat",
                    "Device lock threat"
                ],
                evidence: [
                    "Russia location creates fear",
                    "Threatens iCloud data deletion",
                    "Threatens remote device lock",
                    "Lists multiple service disruptions",
                    "24-hour deadline increases urgency"
                ]
            }
        },
        ollama: {
            summary: "This is a medium-risk phishing email impersonating Apple. It uses fake security alerts with foreign login attempts from Russia and account lock threats to trick recipients into clicking a malicious link and providing their Apple ID credentials.",
            reasoning: "Multiple indicators suggest phishing: (1) Complete authentication failure - all checks failed, indicating sender spoofing. (2) Domain spoofing - apple-support.com and appleid-unlock.com are NOT official Apple domains (official is apple.com or icloud.com). (3) Foreign location exploitation - Moscow, Russia is used to create fear. (4) Urgency - 24-hour deadline with account disablement threat. (5) Data loss threats - iCloud deletion, app loss, device lock. (6) Framework scores in 70-81% range indicate medium-high risk. (7) Apple sends legitimate security alerts, but only through the official Apple ID system at appleid.apple.com, never with external unlock links. (8) Early morning timestamp (2:45 AM) appears suspicious. The email is well-crafted and mimics Apple's security alert format.",
            recommendations: [
                "Delete this email - it is a phishing scam",
                "Do not click any links or provide your Apple ID credentials",
                "Check actual account status by visiting appleid.apple.com directly",
                "Apple sends security alerts through the official Apple ID system, not via external links",
                "If you have concerns, review your account security at appleid.apple.com",
                "If you clicked the link and entered credentials, change your Apple ID password immediately",
                "Enable two-factor authentication for additional security",
                "Review connected devices and sign out suspicious sessions at appleid.apple.com",
                "Report this phishing attempt to Apple at reportphishing@apple.com",
                "Be aware that Apple ID phishing is common due to the value of iCloud data and linked payment methods"
            ]
        }
    },

    // Email 31 - English HIGH TP - Netflix Payment Failure
    {
        id: 31,
        subject: "Netflix: Your payment has failed - Update required",
        from: "billing@netflix-account.com",
        language: "en",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Hi Max,

We're having trouble processing your payment for Netflix.

Account: max.mustermann@email.com
Plan: Premium (4 screens, Ultra HD)
Monthly Fee: $19.99
Payment Status: FAILED

Your Netflix membership will be cancelled in 48 hours if we don't receive payment.

UPDATE PAYMENT METHOD NOW:
http://netflix-billing.com/update?account=max

Why did my payment fail?
• Credit card expired
• Insufficient funds
• Bank declined the transaction
• Billing information outdated

What happens if I don't update:
✗ Your account will be cancelled
✗ You'll lose access to all content
✗ Your viewing history will be deleted
✗ Your profiles and preferences will be lost
✗ You'll need to re-subscribe and start over

Update your payment information now to continue enjoying Netflix.

We accept:
• Credit/Debit Cards (Visa, Mastercard, Amex)
• PayPal
• Gift Cards

Don't lose access to your favorite shows and movies!

Questions? Visit netflix.com/help

Netflix, Inc.
100 Winchester Circle
Los Gatos, CA 95032, USA

This is an automated billing notification.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 89,
                patterns: [
                    "Urgency keyword: failed",
                    "Urgency keyword: FAILED",
                    "Urgency keyword: cancelled in 48 hours",
                    "Urgency keyword: Don't lose access",
                    "Suspicious URL detected",
                    "Payment request",
                    "Multiple threat scenarios"
                ],
                evidence: [
                    "Payment failure creates immediate concern",
                    "48-hour cancellation deadline creates pressure",
                    "Domain netflix-account.com is suspicious",
                    "Threatens account cancellation and data loss",
                    "Lists multiple consequences to increase fear",
                    "Requests payment information update"
                ]
            },
            owasp: {
                score: 83,
                patterns: [
                    "Malicious redirect detected",
                    "Payment information harvesting",
                    "Account tracking parameter"
                ],
                evidence: [
                    "Non-Netflix domain (netflix-billing.com)",
                    "URL designed to collect payment information",
                    "Account parameter suggests tracking",
                    "HTTP instead of HTTPS for payment processing"
                ]
            },
            nist: {
                score: 88,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "Complete authentication failure",
                    "Official Netflix uses netflix.com",
                    "netflix-account.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 85,
                patterns: [
                    "Payment update via email link",
                    "Financial information request",
                    "Security policy violation"
                ],
                evidence: [
                    "Requests payment update via email link",
                    "Netflix handles billing through official account portal",
                    "Violates payment security practices",
                    "Legitimate billing updates processed through netflix.com/account"
                ]
            },
            nessus: {
                score: 82,
                patterns: [
                    "Netflix billing scam",
                    "Payment failure phishing"
                ],
                evidence: [
                    "Matches known Netflix phishing campaigns",
                    "Payment failure theme is extremely common",
                    "Similar attacks widely documented",
                    "Netflix is frequently impersonated"
                ]
            },
            openvas: {
                score: 84,
                patterns: [
                    "Service loss fear manipulation",
                    "Data deletion threat",
                    "Account cancellation pressure"
                ],
                evidence: [
                    "Threatens account cancellation in 48 hours",
                    "Threatens viewing history deletion",
                    "Threatens profile and preference loss",
                    "Exploits fear of losing entertainment access",
                    "Mentions favorite shows to create emotional connection"
                ]
            }
        },
        ollama: {
            summary: "This is a high-confidence phishing email impersonating Netflix. It uses fake payment failure notifications to trick recipients into clicking a malicious link and providing credit card information and payment details.",
            reasoning: "Critical phishing indicators across all frameworks: (1) Complete authentication failure - all checks failed, confirming sender spoofing. (2) Domain spoofing - netflix-account.com and netflix-billing.com are NOT official Netflix domains (official is netflix.com). (3) Payment information request - directs to fake payment page to collect credit card details. (4) Multiple threats - account cancellation, content loss, viewing history deletion, profile loss. (5) 48-hour deadline creates urgency. (6) All frameworks scored 82%+ indicating unanimous high-risk assessment. (7) Netflix handles all billing through the official account portal at netflix.com/account, never via email links. (8) The professional formatting with plan details and legal address is designed to appear legitimate. (9) Netflix billing scams are extremely common due to the widespread use of the service. This email could lead to credit card fraud if victims provide their payment information.",
            recommendations: [
                "Delete this email immediately - it is a phishing scam",
                "Do not click any links or provide payment information",
                "Check your actual Netflix billing status at netflix.com/account",
                "Netflix sends payment notifications through the official website and app, not via email payment links",
                "If you clicked the link and entered payment information, contact your bank immediately",
                "Monitor your credit card statements for unauthorized charges",
                "Change your Netflix password if you provided credentials",
                "Report this phishing attempt to Netflix at phishing@netflix.com",
                "Be aware that Netflix billing scams are extremely common",
                "Legitimate Netflix billing issues are resolved through the account portal at netflix.com/account"
            ]
        }
    },

    // Email 32 - English LOW TN - LinkedIn Connection Request
    {
        id: 32,
        subject: "Sarah Johnson wants to connect on LinkedIn",
        from: "messages-noreply@linkedin.com",
        language: "en",
        riskLevel: "LOW",
        classification: "TN",
        body: `Hi Max,

Sarah Johnson wants to connect with you on LinkedIn.

Sarah Johnson
Senior Product Manager at Google
San Francisco Bay Area

You both know 12 people in common.

View Sarah's profile: www.linkedin.com/in/sarah-johnson-google

Accept invitation: www.linkedin.com/invitations/accept?invitation=123456

Decline invitation: www.linkedin.com/invitations/decline?invitation=123456

You're receiving connection request emails. Unsubscribe:
www.linkedin.com/e/v2/settings/email-frequency

This email was intended for Max Mustermann. Learn why we included this:
www.linkedin.com/e/v2/help/why-email

LinkedIn Ireland Unlimited Company
Wilton Plaza, Wilton Place
Dublin 2, Ireland`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 13,
                patterns: [],
                evidence: [
                    "No urgency keywords",
                    "Standard connection request format",
                    "Professional networking language",
                    "No suspicious requests",
                    "Provides unsubscribe option"
                ]
            },
            owasp: {
                score: 9,
                patterns: [],
                evidence: [
                    "All URLs point to official linkedin.com domain",
                    "No suspicious links",
                    "Standard LinkedIn notification format",
                    "Proper invitation management options"
                ]
            },
            nist: {
                score: 7,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain matches LinkedIn",
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 11,
                patterns: [],
                evidence: [
                    "No sensitive data requests",
                    "Standard networking communication",
                    "GDPR-compliant unsubscribe option",
                    "Appropriate data handling"
                ]
            },
            nessus: {
                score: 8,
                patterns: [],
                evidence: [
                    "No malware signatures",
                    "No exploit attempts",
                    "Clean connection request"
                ]
            },
            openvas: {
                score: 10,
                patterns: [],
                evidence: [
                    "No vulnerability indicators",
                    "Legitimate professional networking communication",
                    "Standard LinkedIn notification format"
                ]
            }
        },
        ollama: {
            summary: "This is a legitimate connection request notification from LinkedIn. All authentication checks passed perfectly, and the email follows standard LinkedIn notification practices.",
            reasoning: "All indicators confirm legitimacy: (1) Perfect authentication - DMARC, SPF, DKIM all passed, confirming the email genuinely came from LinkedIn servers. (2) Official domain - messages-noreply@linkedin.com is the correct domain for LinkedIn notifications. (3) Standard format - includes connection requester information, mutual connections, profile link, and invitation management options. (4) All links point to official linkedin.com domain. (5) Professional networking language and structure. (6) Provides GDPR-compliant unsubscribe option. (7) All frameworks scored very low (7-13%) indicating minimal risk. (8) No urgency tactics, no payment requests, no suspicious elements. (9) Explains why the email was sent and provides help link. (10) LinkedIn connection requests are a normal part of professional networking.",
            recommendations: [
                "Safe to read - this is a legitimate LinkedIn connection request",
                "Sarah Johnson wants to connect with you on LinkedIn",
                "You have 12 mutual connections",
                "Review Sarah's profile before accepting the connection",
                "Accept or decline the invitation through the provided links",
                "Manage your LinkedIn email preferences if you receive too many notifications",
                "No security action required"
            ]
        }
    }
];

    // Email 33 - English MEDIUM TP - WhatsApp Account Verification
    {
        id: 33,
        subject: "WhatsApp: Verify your account to continue using the service",
        from: "verify@whatsapp-service.com",
        language: "en",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Hello,

Your WhatsApp account requires verification to continue using the service.

Phone Number: +49 176 xxxxxxx90
Account Status: Pending Verification
Verification Required By: February 11, 2026

Due to recent policy updates, all WhatsApp users must verify their accounts.

VERIFY YOUR ACCOUNT NOW:
http://whatsapp-verify.com/account?phone=49176

If you don't verify within 24 hours:
• Your account will be temporarily suspended
• You won't be able to send or receive messages
• Your chat history may be lost
• You'll need to re-register your phone number

Verification takes only 2 minutes.

Why is this necessary?
WhatsApp is implementing new security measures to protect user accounts from unauthorized access.

Verify now to keep using WhatsApp.

WhatsApp LLC
1601 Willow Road
Menlo Park, CA 94025, USA

This is an automated security message.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 69,
                patterns: [
                    "Urgency keyword: requires verification",
                    "Urgency keyword: 24 hours",
                    "Urgency keyword: suspended",
                    "Urgency keyword: lost",
                    "Suspicious URL detected",
                    "Account suspension threat"
                ],
                evidence: [
                    "Verification requirement creates urgency",
                    "24-hour deadline creates pressure",
                    "Threatens account suspension",
                    "Threatens chat history loss",
                    "Domain whatsapp-service.com is suspicious",
                    "Policy update excuse is common tactic"
                ]
            },
            owasp: {
                score: 63,
                patterns: [
                    "Suspicious URL structure",
                    "Account verification scam",
                    "Phone parameter tracking"
                ],
                evidence: [
                    "Non-WhatsApp domain (whatsapp-verify.com)",
                    "URL designed to collect account information",
                    "Phone parameter suggests targeting",
                    "HTTP instead of HTTPS for verification"
                ]
            },
            nist: {
                score: 74,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official WhatsApp uses whatsapp.com",
                    "whatsapp-service.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 67,
                patterns: [
                    "Account verification via email link",
                    "Security policy exploitation"
                ],
                evidence: [
                    "Requests verification via email link",
                    "WhatsApp verifies accounts through the app, not email",
                    "Violates mobile app security procedures"
                ]
            },
            nessus: {
                score: 61,
                patterns: [
                    "WhatsApp verification scam",
                    "Account suspension theme"
                ],
                evidence: [
                    "Matches known WhatsApp phishing campaigns",
                    "Account verification theme is common",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 65,
                patterns: [
                    "Communication loss fear",
                    "Chat history loss threat",
                    "Policy update exploitation"
                ],
                evidence: [
                    "Exploits fear of losing communication access",
                    "Threatens chat history loss (personal memories)",
                    "Uses fake policy update as justification",
                    "24-hour deadline creates urgency",
                    "Mentions quick process (2 minutes) to reduce hesitation"
                ]
            }
        },
        ollama: {
            summary: "This is a medium-risk phishing email impersonating WhatsApp. It uses fake account verification requirements to trick recipients into clicking a malicious link that could compromise their WhatsApp account or collect personal information.",
            reasoning: "Multiple indicators suggest phishing: (1) Complete authentication failure - all checks failed, indicating sender spoofing. (2) Domain spoofing - whatsapp-service.com and whatsapp-verify.com are NOT official WhatsApp domains (official is whatsapp.com). (3) Process violation - WhatsApp handles all account verification through the mobile app, never via email links. (4) Urgency - 24-hour deadline with account suspension threat. (5) Chat history loss threat exploits emotional attachment to conversations. (6) Framework scores in 61-74% range indicate medium-high risk. (7) Fake policy update is used as justification, a common social engineering tactic. (8) WhatsApp is owned by Meta and never sends verification requests via email. The email is designed to appear official with company address and security messaging.",
            recommendations: [
                "Delete this email - it is a phishing scam",
                "Do not click any links or provide account information",
                "WhatsApp never sends account verification requests via email",
                "All WhatsApp verification happens within the mobile app",
                "If you have concerns about your account, open the WhatsApp app directly",
                "If you clicked the link, monitor your WhatsApp account for suspicious activity",
                "Enable two-step verification in WhatsApp settings for additional security",
                "Report this phishing attempt to your email provider",
                "Be aware that WhatsApp scams are common due to the app's widespread use",
                "Legitimate WhatsApp communications come through the app, not email"
            ]
        }
    },

    // Email 34 - English HIGH TP - IRS Tax Refund Scam
    {
        id: 34,
        subject: "IRS: You have a pending tax refund of $1,284.50",
        from: "refunds@irs-treasury.gov",
        language: "en",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Dear Taxpayer,

After reviewing your tax return for the 2025 fiscal year, we have determined that you are entitled to a tax refund.

Refund Amount: $1,284.50
Tax Year: 2025
Reference Number: IRS-2026-TXR-8492
Processing Date: February 10, 2026

Reason for Refund:
• Overpaid federal income tax: $987.30
• Earned Income Tax Credit: $297.20

To receive your refund, you must verify your bank account information.

CLAIM YOUR REFUND NOW:
http://irs-refund-processing.com/claim?ref=TXR8492

IMPORTANT: You must claim your refund within 72 hours or it will be forfeited.

Required Information:
• Social Security Number
• Bank Account Number
• Routing Number
• Driver's License Number (for verification)

Your refund will be directly deposited within 5-7 business days after verification.

Failure to claim within 72 hours will result in:
• Refund forfeiture
• Funds returned to US Treasury
• You will need to file an amended return to claim again

Claim your refund now!

Internal Revenue Service
1111 Constitution Ave NW
Washington, DC 20224, USA

This is an official IRS notification.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 91,
                patterns: [
                    "Urgency keyword: pending",
                    "Urgency keyword: IMPORTANT",
                    "Urgency keyword: 72 hours",
                    "Urgency keyword: forfeited",
                    "Suspicious URL detected",
                    "Financial reward (refund)",
                    "Sensitive data request (SSN, bank account)"
                ],
                evidence: [
                    "Tax refund creates positive incentive",
                    "Specific amount ($1,284.50) appears legitimate",
                    "72-hour deadline creates urgency",
                    "Domain irs-treasury.gov is suspicious (official is irs.gov)",
                    "Requests extremely sensitive information (SSN, bank account, driver's license)",
                    "Threatens refund forfeiture"
                ]
            },
            owasp: {
                score: 88,
                patterns: [
                    "Banking information harvesting",
                    "Identity theft attempt",
                    "SSN collection",
                    "Malicious redirect"
                ],
                evidence: [
                    "Non-IRS domain with refund processing path",
                    "URL designed to collect SSN and banking details",
                    "Requests driver's license number - major red flag",
                    "HTTP instead of HTTPS for financial data",
                    "Reference parameter suggests tracking"
                ]
            },
            nist: {
                score: 93,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Government domain spoofing"
                ],
                evidence: [
                    "Complete authentication failure",
                    "Official IRS uses irs.gov",
                    "irs-treasury.gov is fraudulent domain",
                    "Sender spoofing confirmed",
                    "Government impersonation"
                ]
            },
            iso27001: {
                score: 90,
                patterns: [
                    "SSN request via email",
                    "Banking information via email link",
                    "Driver's license request",
                    "Government impersonation"
                ],
                evidence: [
                    "Requests SSN via email - extreme violation",
                    "Asks for bank account and routing numbers",
                    "Requests driver's license for 'verification'",
                    "IRS never requests sensitive information via email",
                    "Violates federal government security protocols"
                ]
            },
            nessus: {
                score: 87,
                patterns: [
                    "IRS refund scam pattern",
                    "Government impersonation detected",
                    "Tax fraud attempt"
                ],
                evidence: [
                    "Matches known IRS phishing campaigns",
                    "Tax refund theme is extremely common",
                    "Similar attacks widely documented",
                    "IRS is frequently impersonated"
                ]
            },
            openvas: {
                score: 89,
                patterns: [
                    "Financial reward manipulation",
                    "Government authority exploitation",
                    "Deadline pressure with forfeiture threat",
                    "Identity theft risk"
                ],
                evidence: [
                    "Uses financial reward to motivate action",
                    "Specific refund amount and breakdown appear legitimate",
                    "Exploits government authority for trust",
                    "Threatens refund forfeiture to create urgency",
                    "72-hour deadline creates pressure",
                    "Requests complete identity theft package (SSN, bank account, driver's license)"
                ]
            }
        },
        ollama: {
            summary: "This is a high-confidence phishing email impersonating the IRS. It uses fake tax refund notifications to trick recipients into providing complete identity theft information including Social Security Numbers, bank account details, and driver's license numbers.",
            reasoning: "Critical phishing indicators across all frameworks: (1) Complete authentication failure - all checks failed, confirming sender spoofing. (2) Domain spoofing - irs-treasury.gov and irs-refund-processing.com are NOT official IRS domains (official is irs.gov). (3) Extreme data requests - asking for SSN, bank account, routing number, and driver's license via email is a massive red flag. (4) Process violation - the IRS NEVER initiates contact via email about refunds or requests sensitive information electronically. (5) Financial reward tactic - uses positive incentive (refund) instead of threats. (6) Urgency - 72-hour deadline with forfeiture threat. (7) All frameworks scored 87%+ indicating unanimous critical-risk assessment. (8) The IRS communicates about refunds exclusively through official mail or through the IRS.gov website. (9) Professional formatting with reference numbers and official address is designed to appear legitimate. This email could lead to complete identity theft and bank account fraud if victims provide the requested information.",
            recommendations: [
                "Delete this email immediately - it is a dangerous phishing scam",
                "Do not click any links or provide any information",
                "NEVER provide SSN, bank account details, or driver's license via email",
                "The IRS NEVER initiates contact via email about refunds",
                "Check your actual refund status at irs.gov or by calling 1-800-829-1040",
                "The IRS communicates about refunds through official mail only",
                "If you clicked the link and entered information, take immediate action: (1) Contact the IRS immediately at 1-800-829-1040, (2) Contact your bank if you provided account information, (3) Place a fraud alert with credit bureaus, (4) Monitor your credit report for identity theft, (5) File a report with the FTC at identitytheft.gov",
                "Report this scam to the IRS at phishing@irs.gov",
                "Be aware that IRS refund scams are extremely common, especially during tax season",
                "Legitimate IRS refunds are processed automatically and deposited to the account on your tax return"
            ]
        }
    },

    // Email 35 - English LOW TN - Amazon Order Confirmation
    {
        id: 35,
        subject: "Your Amazon.com order has shipped",
        from: "ship-confirm@amazon.com",
        language: "en",
        riskLevel: "LOW",
        classification: "TN",
        body: `Hello Max Mustermann,

Your Amazon.com order has been shipped!

Order Number: 112-8475692-3847561
Order Date: February 9, 2026

Shipping Details:
Carrier: UPS
Tracking Number: 1Z999AA10123456784
Estimated Delivery: February 12, 2026

Items Shipped:
1x Apple AirPods Pro (2nd Generation)
   Sold by: Amazon.com Services LLC
   Price: $249.00

Shipping Address:
Max Mustermann
Hauptstraße 123
10115 Berlin
Germany

Track your package:
www.amazon.com/progress-tracker/package?orderID=112-8475692-3847561

Order Summary:
Items: $249.00
Shipping & Handling: $0.00
Total before tax: $249.00
Estimated tax: $47.31
Order Total: $296.31

Payment Method: Visa ending in 1234

Need help with your order?
Visit Your Orders: www.amazon.com/your-orders
Customer Service: www.amazon.com/contact-us

Thank you for shopping with us!

Amazon.com, Inc.
410 Terry Avenue North
Seattle, WA 98109, USA`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 14,
                patterns: [],
                evidence: [
                    "No urgency keywords",
                    "Standard shipping confirmation format",
                    "Professional e-commerce language",
                    "Complete order details provided",
                    "No suspicious requests"
                ]
            },
            owasp: {
                score: 9,
                patterns: [],
                evidence: [
                    "All URLs point to official amazon.com domain",
                    "No suspicious links",
                    "Standard order confirmation format",
                    "Proper tracking and order management links"
                ]
            },
            nist: {
                score: 7,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain matches Amazon",
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 11,
                patterns: [],
                evidence: [
                    "No sensitive data requests",
                    "Standard order communication",
                    "Provides proper contact information",
                    "Appropriate data handling"
                ]
            },
            nessus: {
                score: 8,
                patterns: [],
                evidence: [
                    "No malware signatures",
                    "No exploit attempts",
                    "Clean shipping confirmation"
                ]
            },
            openvas: {
                score: 10,
                patterns: [],
                evidence: [
                    "No vulnerability indicators",
                    "Legitimate e-commerce confirmation",
                    "Standard Amazon shipping notification format"
                ]
            }
        },
        ollama: {
            summary: "This is a legitimate shipping confirmation email from Amazon. All authentication checks passed perfectly, and the email follows standard order confirmation practices with complete order details and tracking information.",
            reasoning: "All indicators confirm legitimacy: (1) Perfect authentication - DMARC, SPF, DKIM all passed, confirming the email genuinely came from Amazon servers. (2) Official domain - ship-confirm@amazon.com is the correct domain for Amazon shipping confirmations. (3) Standard format - includes complete order details (order number, items, pricing, shipping address, tracking information). (4) All links point to official amazon.com domain. (5) Professional e-commerce language and structure. (6) Provides legitimate customer service options. (7) All frameworks scored very low (7-14%) indicating minimal risk. (8) No urgency tactics, no payment requests, no suspicious elements. (9) Order number format matches Amazon standards. (10) Shows last 4 digits of payment method, which is standard practice.",
            recommendations: [
                "Safe to read - this is a legitimate Amazon shipping confirmation",
                "Your order for Apple AirPods Pro has shipped via UPS",
                "Expected delivery: February 12, 2026",
                "Track your package using the provided link or tracking number",
                "Keep this email for your order records",
                "Contact Amazon customer service if you have any issues with delivery",
                "No security action required"
            ]
        }
    },

    // Email 36 - English MEDIUM TP - Microsoft Security Alert
    {
        id: 36,
        subject: "Microsoft: Unusual sign-in activity from new location",
        from: "account-security@microsoft-alerts.com",
        language: "en",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Hello,

We detected a new sign-in to your Microsoft account from an unusual location.

Account: max.mustermann@email.com
Sign-in Location: Lagos, Nigeria
Device: Android Phone
Time: February 10, 2026, 3:15 AM EST
IP Address: 197.210.xxx.xxx

Was this you?

If you don't recognize this sign-in, your account may be at risk.

SECURE YOUR ACCOUNT:
http://microsoft-account-security.com/verify?session=MS2026

Recommended Actions:
1. Review recent activity
2. Change your password
3. Enable two-factor authentication
4. Check connected devices

If you don't respond within 12 hours, we'll assume this sign-in was authorized.

What's at risk:
• Access to your emails (Outlook)
• OneDrive files and documents
• Office 365 applications
• Skype conversations
• Xbox account and purchases

Protect your account now.

Microsoft Corporation
One Microsoft Way
Redmond, WA 98052, USA

This is an automated security notification.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 73,
                patterns: [
                    "Urgency keyword: Unusual activity",
                    "Urgency keyword: at risk",
                    "Urgency keyword: SECURE YOUR ACCOUNT",
                    "Urgency keyword: 12 hours",
                    "Suspicious URL detected",
                    "Foreign location (Nigeria)"
                ],
                evidence: [
                    "Unusual sign-in creates concern",
                    "Foreign location (Lagos, Nigeria) increases fear",
                    "12-hour deadline creates pressure",
                    "Early morning timestamp (3:15 AM) appears suspicious",
                    "Domain microsoft-alerts.com is suspicious",
                    "Lists multiple services at risk"
                ]
            },
            owasp: {
                score: 67,
                patterns: [
                    "Suspicious URL structure",
                    "Credential harvesting attempt",
                    "Session tracking parameter"
                ],
                evidence: [
                    "Non-Microsoft domain (microsoft-account-security.com)",
                    "URL designed to collect Microsoft credentials",
                    "Session parameter suggests tracking",
                    "HTTP instead of HTTPS for account security"
                ]
            },
            nist: {
                score: 77,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Microsoft uses microsoft.com",
                    "microsoft-alerts.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 70,
                patterns: [
                    "Account security action via email link",
                    "Password change through email"
                ],
                evidence: [
                    "Requests security action via email link",
                    "Microsoft handles security through official website/app",
                    "Violates security notification procedures"
                ]
            },
            nessus: {
                score: 65,
                patterns: [
                    "Microsoft security alert scam",
                    "Foreign login theme"
                ],
                evidence: [
                    "Matches known Microsoft phishing campaigns",
                    "Foreign login alert is common tactic",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 69,
                patterns: [
                    "Foreign location fear manipulation",
                    "Account compromise threat",
                    "Multiple service risk exploitation"
                ],
                evidence: [
                    "Nigeria location creates fear (common scam origin)",
                    "Early morning timestamp appears suspicious",
                    "Lists multiple services at risk (Outlook, OneDrive, Office, Skype, Xbox)",
                    "12-hour deadline creates urgency",
                    "Exploits fear of account compromise"
                ]
            }
        },
        ollama: {
            summary: "This is a medium-risk phishing email impersonating Microsoft security alerts. It uses fake foreign login attempts from Nigeria to create fear and urgency, tricking recipients into clicking a malicious link and providing their Microsoft account credentials.",
            reasoning: "Multiple indicators suggest phishing: (1) Complete authentication failure - all checks failed, indicating sender spoofing. (2) Domain spoofing - microsoft-alerts.com and microsoft-account-security.com are NOT official Microsoft domains (official is microsoft.com). (3) Foreign location exploitation - Lagos, Nigeria is used to create fear (commonly associated with scams). (4) Urgency - 12-hour deadline and immediate action request. (5) Early morning timestamp (3:15 AM EST) appears suspicious. (6) Framework scores in 65-77% range indicate medium-high risk. (7) Microsoft sends legitimate security alerts, but only through the official Microsoft account system, never with external security links. (8) Lists multiple services at risk (Outlook, OneDrive, Office, Skype, Xbox) to increase fear. The email is well-crafted and mimics Microsoft's security alert format.",
            recommendations: [
                "Delete this email - it is a phishing scam",
                "Do not click any links or provide your Microsoft credentials",
                "Check actual account activity by visiting account.microsoft.com directly",
                "Microsoft sends security alerts through the official account system, not via external links",
                "If you have concerns, review your account activity at account.microsoft.com/activity",
                "If you clicked the link and entered credentials, change your Microsoft password immediately",
                "Enable two-factor authentication for additional security",
                "Review connected devices and sign out suspicious sessions",
                "Report this phishing attempt to Microsoft",
                "Be aware that foreign location alerts (especially Nigeria, Russia, China) are common phishing tactics"
            ]
        }
    },

    // Email 37 - English HIGH TP - Bank of America Account Alert
    {
        id: 37,
        subject: "Bank of America: Suspicious activity detected on your account",
        from: "alerts@bankofamerica-security.com",
        language: "en",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Dear Valued Customer,

We have detected suspicious activity on your Bank of America account and have temporarily restricted access for your protection.

Account: Checking Account ****3456
Date: February 10, 2026
Status: RESTRICTED

Suspicious Transactions Detected:
• $2,450.00 - Online Purchase - Amazon.com
• $1,875.00 - Wire Transfer - International
• $950.00 - ATM Withdrawal - Location Unknown

Total Suspicious Amount: $5,275.00

IMMEDIATE ACTION REQUIRED:
http://bankofamerica-verify.com/secure?account=3456

To restore full access to your account, please:
1. Verify your identity
2. Confirm or dispute the transactions
3. Update your security information

You must respond within 24 hours or your account will be permanently closed and funds will be held pending investigation.

Required Information for Verification:
• Full Account Number
• Social Security Number
• Debit Card Number and PIN
• Online Banking Password
• Mother's Maiden Name

After verification, your account will be restored within 2-4 hours.

Failure to verify will result in:
• Permanent account closure
• Funds held for 90 days
• Credit score impact
• Inability to open new accounts

Protect your account now!

Bank of America, N.A.
100 North Tryon Street
Charlotte, NC 28255, USA

This is an automated fraud prevention alert.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 95,
                patterns: [
                    "Urgency keyword: Suspicious activity",
                    "Urgency keyword: RESTRICTED",
                    "Urgency keyword: IMMEDIATE ACTION",
                    "Urgency keyword: 24 hours",
                    "Urgency keyword: permanently closed",
                    "Suspicious URL detected",
                    "Multiple threat scenarios",
                    "Extreme sensitive data request"
                ],
                evidence: [
                    "Account restriction creates immediate panic",
                    "Lists specific suspicious transactions with amounts",
                    "24-hour deadline with permanent closure threat",
                    "Domain bankofamerica-security.com is suspicious",
                    "Requests EXTREME sensitive information (account number, SSN, PIN, password)",
                    "Threatens credit score impact",
                    "90-day fund hold creates severe fear"
                ]
            },
            owasp: {
                score: 94,
                patterns: [
                    "Banking credential harvesting",
                    "PIN collection attempt",
                    "Password theft",
                    "SSN collection",
                    "Complete identity theft package"
                ],
                evidence: [
                    "Non-Bank of America domain with verification path",
                    "Requests complete banking credentials including PIN",
                    "Asks for online banking password - extreme red flag",
                    "Requests SSN and mother's maiden name",
                    "HTTP instead of HTTPS for banking",
                    "This is a complete identity theft kit"
                ]
            },
            nist: {
                score: 96,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Financial institution spoofing"
                ],
                evidence: [
                    "Complete authentication failure",
                    "Official Bank of America uses bankofamerica.com",
                    "bankofamerica-security.com is fraudulent domain",
                    "Sender spoofing confirmed",
                    "Financial institution impersonation"
                ]
            },
            iso27001: {
                score: 95,
                patterns: [
                    "PIN request via email",
                    "Password request via email",
                    "SSN request via email",
                    "Complete credential collection",
                    "Banking security violation"
                ],
                evidence: [
                    "Requests debit card PIN via email - NEVER legitimate",
                    "Asks for online banking password - extreme violation",
                    "Requests SSN and security questions",
                    "Banks NEVER request PINs or passwords via email",
                    "Violates all banking security standards",
                    "This is a complete account takeover attempt"
                ]
            },
            nessus: {
                score: 93,
                patterns: [
                    "Bank fraud scam pattern",
                    "Account takeover attempt",
                    "Known banking phishing signature"
                ],
                evidence: [
                    "Matches known banking phishing campaigns",
                    "Account restriction theme is extremely common",
                    "Similar attacks widely documented",
                    "Banks are frequently impersonated"
                ]
            },
            openvas: {
                score: 94,
                patterns: [
                    "Financial loss fear manipulation",
                    "Account closure threat",
                    "Credit score impact threat",
                    "Fund holding threat (90 days)",
                    "Complete identity theft attempt"
                ],
                evidence: [
                    "Lists specific suspicious transactions to appear legitimate",
                    "Threatens permanent account closure",
                    "Threatens 90-day fund hold - creates extreme fear",
                    "Mentions credit score impact - additional fear",
                    "24-hour deadline creates panic",
                    "Requests complete identity theft package (account, SSN, PIN, password, security questions)"
                ]
            }
        },
        ollama: {
            summary: "This is a CRITICAL phishing email impersonating Bank of America. It uses fake fraud alerts with account restrictions to panic recipients into providing complete banking credentials including PINs and passwords, leading to immediate account takeover and financial fraud.",
            reasoning: "CRITICAL phishing indicators across all frameworks: (1) Complete authentication failure - all checks failed, confirming sender spoofing. (2) Domain spoofing - bankofamerica-security.com and bankofamerica-verify.com are NOT official Bank of America domains (official is bankofamerica.com). (3) EXTREME data requests - asking for account number, SSN, debit card PIN, online banking password, and security questions via email is NEVER legitimate. (4) Process violation - banks NEVER request PINs or passwords under any circumstances, especially not via email. (5) Multiple severe threats - permanent closure, 90-day fund hold, credit score impact. (6) All frameworks scored 93%+ indicating unanimous critical-risk assessment. (7) The specific transaction details are designed to appear legitimate and create urgency. (8) Bank of America handles fraud alerts exclusively through the mobile app, phone calls, or secure messaging within online banking. (9) This email is designed for immediate account takeover - providing the requested information would give attackers complete control of the account. This is one of the most dangerous types of phishing attacks.",
            recommendations: [
                "Delete this email immediately - this is an EXTREMELY dangerous phishing scam",
                "Do not click any links or provide ANY information",
                "NEVER provide your PIN or online banking password to anyone, ever",
                "Banks NEVER request PINs, passwords, or SSNs via email",
                "Check your actual account by calling Bank of America at 1-800-432-1000 or visiting bankofamerica.com",
                "If you clicked the link and entered ANY information, take IMMEDIATE action: (1) Call Bank of America immediately at 1-800-432-1000, (2) Change your online banking password, (3) Request new debit cards, (4) Monitor your account for unauthorized transactions, (5) Place fraud alerts with credit bureaus, (6) File a police report",
                "Enable account alerts for all transactions",
                "Report this scam to Bank of America and the FBI's IC3 (ic3.gov)",
                "Be aware that banking phishing is extremely dangerous and can lead to complete account takeover",
                "Legitimate bank fraud alerts come through the mobile app or phone calls, never via email requesting credentials"
            ]
        }
    },

    // Email 38 - English LOW FP - Legitimate Urgent Security Update
    {
        id: 38,
        subject: "URGENT: Critical Security Update Required for Your Router",
        from: "security@tp-link.com",
        language: "en",
        riskLevel: "LOW",
        classification: "FP",
        body: `Dear TP-Link Customer,

A critical security vulnerability has been discovered in your router model that requires immediate attention.

Affected Model: Archer AX6000
Firmware Version: 1.2.3 (Vulnerable)
Severity: HIGH
CVE ID: CVE-2026-12345

Vulnerability Details:
Remote Code Execution vulnerability allows attackers to gain unauthorized access to your network.

IMMEDIATE ACTION REQUIRED:
Update your router firmware to version 1.3.0 or higher.

Download firmware update:
www.tp-link.com/us/support/download/archer-ax6000/#Firmware

Installation Instructions:
1. Download firmware from official TP-Link website
2. Log into your router admin panel (192.168.1.1)
3. Navigate to System Tools > Firmware Upgrade
4. Upload and install the new firmware
5. Router will reboot automatically

Detailed instructions:
www.tp-link.com/us/support/faq/2659/

This is a legitimate security update. Please update as soon as possible to protect your network.

For assistance, contact TP-Link Support:
Phone: 1-866-225-8139
Email: support@tp-link.com

TP-Link Technologies Co., Ltd.
Building 24, Chang'an New District
Shenzhen, China

This is an official security notification.`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 54,
                patterns: [
                    "Urgency keyword: URGENT",
                    "Urgency keyword: Critical",
                    "Urgency keyword: IMMEDIATE ACTION",
                    "Urgency keyword: as soon as possible",
                    "Security vulnerability mentioned",
                    "Technical jargon (CVE, Remote Code Execution)"
                ],
                evidence: [
                    "Subject line in all caps with URGENT",
                    "Critical security vulnerability creates urgency",
                    "Immediate action required",
                    "However, domain is legitimate tp-link.com",
                    "All links point to official TP-Link website",
                    "This is a legitimate security update, not phishing"
                ]
            },
            owasp: {
                score: 16,
                patterns: [],
                evidence: [
                    "All URLs point to official tp-link.com domain",
                    "No suspicious links",
                    "Standard security update notification",
                    "Provides legitimate firmware update process"
                ]
            },
            nist: {
                score: 10,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Sender domain matches TP-Link",
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 22,
                patterns: [
                    "Urgent security action required"
                ],
                evidence: [
                    "Requests immediate firmware update",
                    "However, this is legitimate security practice",
                    "Provides proper update procedures",
                    "No sensitive data requests"
                ]
            },
            nessus: {
                score: 18,
                patterns: [
                    "Urgent security update pattern"
                ],
                evidence: [
                    "Resembles phishing urgency tactics",
                    "However, this is a legitimate security notification",
                    "CVE ID can be verified",
                    "No malware or exploits"
                ]
            },
            openvas: {
                score: 26,
                patterns: [
                    "Security vulnerability exploitation (legitimate)",
                    "Urgency tactics (legitimate reason)"
                ],
                evidence: [
                    "Uses urgency language typical of phishing",
                    "However, security vulnerabilities require urgent action",
                    "This is legitimate security communication",
                    "Provides proper update channels"
                ]
            }
        },
        ollama: {
            summary: "This is a FALSE POSITIVE - a legitimate security notification from TP-Link about a critical router vulnerability. While it uses urgent language typical of phishing, it's an authentic security update that was flagged due to aggressive urgency tactics.",
            reasoning: "This is classified as a FALSE POSITIVE because it appears suspicious but is actually legitimate: (1) Perfect authentication - DMARC, SPF, DKIM all passed, confirming it genuinely came from TP-Link. (2) Official domain - security@tp-link.com is correct for TP-Link security notifications. (3) All links point to legitimate tp-link.com domain. (4) However, ML classifier scored 54% due to extreme urgency language: 'URGENT', 'Critical', 'IMMEDIATE ACTION REQUIRED'. (5) The CVE ID (CVE-2026-12345) can be verified on official vulnerability databases. (6) Security vulnerabilities DO require urgent action, making this legitimate urgency. (7) Provides proper firmware update procedures through official channels. (8) No sensitive data requests - only directs to official website. (9) This demonstrates that legitimate security notifications can trigger phishing detection when they use urgent language, which is necessary for critical vulnerabilities. (10) The line between legitimate security urgency and phishing tactics can be blurry, requiring verification of sender authenticity.",
            recommendations: [
                "This is a legitimate security notification from TP-Link",
                "The urgency is justified - critical vulnerabilities require immediate action",
                "Verify the CVE ID on official vulnerability databases (cve.mitre.org)",
                "Download firmware updates only from the official TP-Link website",
                "Follow the provided instructions to update your router firmware",
                "If you're unsure, visit tp-link.com directly and check for security updates",
                "Contact TP-Link support at the provided phone number if you have questions",
                "Keep your router firmware updated to protect against security vulnerabilities",
                "This email demonstrates why verification is important: legitimate security updates can look urgent",
                "Best practice: Always verify security updates through official channels before taking action"
            ]
        }
    },

    // Email 39 - English MEDIUM TP - Dropbox Storage Full
    {
        id: 39,
        subject: "Dropbox: Your storage is full - Upgrade now",
        from: "no-reply@dropbox-storage.com",
        language: "en",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Hi Max,

Your Dropbox storage is full!

Storage Used: 2.00 GB / 2.00 GB (100%)
Account: max.mustermann@email.com

You can't sync new files until you free up space or upgrade your account.

UPGRADE NOW:
http://dropbox-upgrade.com/plans?user=max

Upgrade Options:
• Plus (2 TB) - $11.99/month
• Professional (3 TB) - $19.99/month
• Business (Unlimited) - $15/user/month

Special Offer: Get 20% off your first year!

What happens if you don't upgrade:
• New files won't sync
• You can't upload new files
• Shared folders may stop working
• You risk losing important data

Upgrade now to keep your files safe and accessible.

Free up space: www.dropbox.com/account/usage
Upgrade account: www.dropbox.com/upgrade

Questions? Contact Dropbox Support
support@dropbox.com

Dropbox, Inc.
1800 Owens Street
San Francisco, CA 94158, USA`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 67,
                patterns: [
                    "Urgency keyword: full",
                    "Urgency keyword: can't sync",
                    "Urgency keyword: Upgrade now",
                    "Urgency keyword: risk losing",
                    "Suspicious URL detected",
                    "Discount offer (20%)"
                ],
                evidence: [
                    "Storage full creates concern",
                    "Can't sync new files creates urgency",
                    "Domain dropbox-storage.com is suspicious",
                    "Threatens data loss",
                    "20% discount adds urgency",
                    "Lists multiple consequences"
                ]
            },
            owasp: {
                score: 61,
                patterns: [
                    "Suspicious URL structure",
                    "Payment page redirect",
                    "User tracking parameter"
                ],
                evidence: [
                    "Non-Dropbox domain (dropbox-upgrade.com)",
                    "URL designed to collect payment information",
                    "User parameter suggests tracking",
                    "HTTP instead of HTTPS for payment"
                ]
            },
            nist: {
                score: 72,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing detected"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Dropbox uses dropbox.com",
                    "dropbox-storage.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 64,
                patterns: [
                    "Payment request via email link",
                    "Subscription upgrade through email"
                ],
                evidence: [
                    "Requests payment via email link",
                    "Dropbox handles upgrades through official website",
                    "Violates payment security practices"
                ]
            },
            nessus: {
                score: 59,
                patterns: [
                    "Dropbox storage scam",
                    "Upgrade pressure theme"
                ],
                evidence: [
                    "Matches known Dropbox phishing campaigns",
                    "Storage full theme is common",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 63,
                patterns: [
                    "Data loss fear manipulation",
                    "Service disruption threats",
                    "Discount urgency"
                ],
                evidence: [
                    "Exploits fear of losing important data",
                    "Threatens sync and upload disruption",
                    "20% discount creates urgency",
                    "Lists multiple consequences to increase fear"
                ]
            }
        },
        ollama: {
            summary: "This is a medium-risk phishing email impersonating Dropbox. It uses fake storage full notifications to trick recipients into clicking a malicious link and providing payment information for a fake upgrade.",
            reasoning: "Multiple indicators suggest phishing: (1) Complete authentication failure - all checks failed, indicating sender spoofing. (2) Domain spoofing - dropbox-storage.com and dropbox-upgrade.com are NOT official Dropbox domains (official is dropbox.com). (3) Payment request - directs to fake payment page for subscription upgrade. (4) Urgency - storage full with sync disruption and data loss threats. (5) Discount offer (20%) adds urgency. (6) Framework scores in 59-72% range indicate medium-high risk. (7) Dropbox sends storage notifications through the official app and website, not via email payment links. (8) The email is well-crafted and uses realistic Dropbox language and pricing.",
            recommendations: [
                "Delete this email - it is a phishing scam",
                "Do not click any links or provide payment information",
                "Check your actual Dropbox storage at dropbox.com directly",
                "Dropbox sends storage notifications through the app and website, not via email payment links",
                "If you want to upgrade, do so only through the official Dropbox website",
                "If you clicked the link and entered payment information, contact your bank immediately",
                "Monitor your credit card statements for unauthorized charges",
                "Report this phishing attempt to Dropbox",
                "Be aware that cloud storage scams exploit fear of data loss",
                "Legitimate Dropbox upgrades are processed through dropbox.com only"
            ]
        }
    },

    // Email 40 - English HIGH TP - Wells Fargo Account Verification
    {
        id: 40,
        subject: "Wells Fargo: Verify your account to avoid suspension",
        from: "verify@wellsfargo-online.com",
        language: "en",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Dear Wells Fargo Customer,

Due to recent security updates, we require all customers to verify their account information.

Account: Checking Account ****7890
Verification Status: PENDING
Deadline: February 11, 2026

VERIFY YOUR ACCOUNT NOW:
http://wellsfargo-verify.com/secure?ref=WF2026

If you don't verify by the deadline, your account will be suspended.

Required Verification Steps:
1. Confirm your identity
2. Verify your contact information
3. Update security questions
4. Confirm your debit card details

This is required by federal banking regulations.

Consequences of not verifying:
• Account suspension
• Online banking access blocked
• Debit card deactivated
• Bill payments stopped
• Unable to access funds

Verification takes only 3-5 minutes.

Protect your account by verifying now.

Wells Fargo Bank, N.A.
420 Montgomery Street
San Francisco, CA 94104, USA

This is an automated security notification.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 90,
                patterns: [
                    "Urgency keyword: Verify",
                    "Urgency keyword: PENDING",
                    "Urgency keyword: suspension",
                    "Urgency keyword: Deadline",
                    "Suspicious URL detected",
                    "Multiple threat scenarios"
                ],
                evidence: [
                    "Account verification requirement creates urgency",
                    "Specific deadline creates pressure",
                    "Domain wellsfargo-online.com is suspicious",
                    "Threatens account suspension",
                    "Lists multiple consequences",
                    "Federal regulation excuse is common tactic"
                ]
            },
            owasp: {
                score: 85,
                patterns: [
                    "Banking credential harvesting",
                    "Identity theft attempt",
                    "Debit card information collection"
                ],
                evidence: [
                    "Non-Wells Fargo domain with verification path",
                    "URL designed to collect banking credentials",
                    "Requests debit card details",
                    "HTTP instead of HTTPS for banking"
                ]
            },
            nist: {
                score: 91,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Financial institution spoofing"
                ],
                evidence: [
                    "Complete authentication failure",
                    "Official Wells Fargo uses wellsfargo.com",
                    "wellsfargo-online.com is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 88,
                patterns: [
                    "Account verification via email link",
                    "Debit card details request",
                    "Banking security violation"
                ],
                evidence: [
                    "Requests account verification via email",
                    "Asks for debit card details",
                    "Banks verify accounts through secure in-app processes",
                    "Violates banking security standards"
                ]
            },
            nessus: {
                score: 83,
                patterns: [
                    "Wells Fargo phishing pattern",
                    "Account verification scam"
                ],
                evidence: [
                    "Matches known Wells Fargo phishing campaigns",
                    "Account verification theme is common",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 86,
                patterns: [
                    "Account suspension threat",
                    "Multiple service disruption threats",
                    "Regulatory compliance exploitation"
                ],
                evidence: [
                    "Threatens account suspension",
                    "Lists multiple consequences (online banking, debit card, bill payments, fund access)",
                    "Exploits federal regulation for credibility",
                    "Deadline creates urgency",
                    "Quick process (3-5 minutes) reduces hesitation"
                ]
            }
        },
        ollama: {
            summary: "This is a high-confidence phishing email impersonating Wells Fargo. It uses fake account verification requirements with suspension threats to trick recipients into providing banking credentials and debit card information.",
            reasoning: "Critical phishing indicators across all frameworks: (1) Complete authentication failure - all checks failed, confirming sender spoofing. (2) Domain spoofing - wellsfargo-online.com and wellsfargo-verify.com are NOT official Wells Fargo domains (official is wellsfargo.com). (3) Process violation - banks don't require account verification via email links. (4) Multiple threats - account suspension, online banking block, debit card deactivation, bill payment stoppage, fund inaccessibility. (5) Deadline creates urgency. (6) All frameworks scored 83%+ indicating unanimous high-risk assessment. (7) Federal regulation excuse is a common social engineering tactic. (8) Wells Fargo handles all account security through the official website or mobile app. (9) The professional formatting with account details and legal address is designed to appear legitimate. This email could lead to account takeover and financial fraud.",
            recommendations: [
                "Delete this email immediately - it is a phishing scam",
                "Do not click any links or provide any information",
                "Banks never require account verification via email links",
                "Check your actual account status at wellsfargo.com or call 1-800-869-3557",
                "If you clicked the link and entered information, contact Wells Fargo immediately",
                "Change your online banking password if you provided credentials",
                "Monitor your account for unauthorized transactions",
                "Report this phishing attempt to Wells Fargo and the FBI's IC3",
                "Be aware that banking phishing is extremely common",
                "Legitimate bank security updates are handled through the mobile app or secure website"
            ]
        }
    },

    // Emails 41-48: Adding remaining 8 English emails to complete the English section
    // Email 41 - English LOW TN - GitHub Pull Request Notification
    {
        id: 41,
        subject: "New pull request on your repository",
        from: "notifications@github.com",
        language: "en",
        riskLevel: "LOW",
        classification: "TN",
        body: `Hi Max,

A new pull request has been opened on your repository.

Repository: max-mustermann/defendersim
Pull Request #42: Add email dataset expansion

Opened by: sarah-dev
Status: Open
Changes: +1,247 lines, -89 lines

Description:
Expanded email dataset from 15 to 60 emails with multilingual support (German, English, French). Added complete framework analysis for all emails.

View pull request:
www.github.com/max-mustermann/defendersim/pull/42

Files changed:
• frontend/js/emailData.js (+1,156 lines)
• README.md (+91 lines)

Review and merge:
www.github.com/max-mustermann/defendersim/pull/42/files

Manage notifications:
www.github.com/settings/notifications

GitHub, Inc.
88 Colin P Kelly Jr Street
San Francisco, CA 94107, USA`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 12,
                patterns: [],
                evidence: [
                    "No urgency keywords",
                    "Standard GitHub notification format",
                    "Professional development language",
                    "No suspicious requests"
                ]
            },
            owasp: {
                score: 8,
                patterns: [],
                evidence: [
                    "All URLs point to official github.com domain",
                    "No suspicious links",
                    "Standard pull request notification"
                ]
            },
            nist: {
                score: 7,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 10,
                patterns: [],
                evidence: [
                    "No sensitive data requests",
                    "Standard development communication"
                ]
            },
            nessus: {
                score: 8,
                patterns: [],
                evidence: [
                    "No malware signatures",
                    "Clean notification"
                ]
            },
            openvas: {
                score: 9,
                patterns: [],
                evidence: [
                    "No vulnerability indicators",
                    "Legitimate developer notification"
                ]
            }
        },
        ollama: {
            summary: "This is a legitimate pull request notification from GitHub. All authentication checks passed perfectly, and the email follows standard GitHub notification practices.",
            reasoning: "All indicators confirm legitimacy: (1) Perfect authentication - DMARC, SPF, DKIM all passed. (2) Official domain - notifications@github.com is correct. (3) Standard format with repository details, pull request information, and file changes. (4) All links point to official github.com domain. (5) All frameworks scored very low (7-12%) indicating minimal risk. (6) No urgency tactics, no payment requests, no suspicious elements.",
            recommendations: [
                "Safe to read - this is a legitimate GitHub notification",
                "Review the pull request at your convenience",
                "Check the changes before merging",
                "No security action required"
            ]
        }
    },

    // Email 42 - English MEDIUM TP - Spotify Premium Expiration
    {
        id: 42,
        subject: "Spotify: Your Premium subscription is expiring",
        from: "billing@spotify-premium.com",
        language: "en",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Hi Max,

Your Spotify Premium subscription is expiring soon.

Account: max.mustermann@email.com
Plan: Spotify Premium Individual
Expiration: February 12, 2026

RENEW NOW: http://spotify-renewal.com/subscribe

After expiration:
• Ads will return
• Limited skips
• No offline listening
• Lower audio quality

Renew today and save 20%!
Regular: $9.99/month
Today: $7.99/month

Offer expires in 48 hours!

Keep enjoying Premium features.

Spotify AB
Regeringsgatan 19
Stockholm, Sweden`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 68,
                patterns: [
                    "Urgency keyword: expiring",
                    "Urgency keyword: 48 hours",
                    "Suspicious URL detected",
                    "Discount offer (20%)"
                ],
                evidence: [
                    "Subscription expiration creates urgency",
                    "48-hour deadline for discount",
                    "Domain spotify-premium.com is suspicious",
                    "20% discount adds pressure"
                ]
            },
            owasp: {
                score: 62,
                patterns: [
                    "Payment information harvesting",
                    "Suspicious URL"
                ],
                evidence: [
                    "Non-Spotify domain (spotify-renewal.com)",
                    "URL designed to collect payment information"
                ]
            },
            nist: {
                score: 73,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Spotify uses spotify.com",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 65,
                patterns: [
                    "Payment request via email link"
                ],
                evidence: [
                    "Requests payment via email link",
                    "Violates payment security practices"
                ]
            },
            nessus: {
                score: 60,
                patterns: [
                    "Spotify subscription scam"
                ],
                evidence: [
                    "Matches known Spotify phishing campaigns"
                ]
            },
            openvas: {
                score: 64,
                patterns: [
                    "Service loss fear",
                    "Discount urgency"
                ],
                evidence: [
                    "Exploits fear of losing Premium features",
                    "20% discount creates urgency"
                ]
            }
        },
        ollama: {
            summary: "This is a medium-risk phishing email impersonating Spotify. It uses fake subscription expiration notifications to trick recipients into providing payment information.",
            reasoning: "Multiple indicators suggest phishing: (1) Complete authentication failure. (2) Domain spoofing - spotify-premium.com is NOT official. (3) Payment request via email link. (4) Urgency with 48-hour deadline. (5) Framework scores in 60-73% range indicate medium-high risk.",
            recommendations: [
                "Delete this email - it is a phishing scam",
                "Do not click any links or provide payment information",
                "Check your actual Spotify subscription at spotify.com",
                "Renew only through the official Spotify website or app",
                "Report this phishing attempt to Spotify"
            ]
        }
    },

    // Email 43 - English LOW TN - Slack Workspace Invitation
    {
        id: 43,
        subject: "You've been invited to join Tech Startup workspace on Slack",
        from: "feedback@slack.com",
        language: "en",
        riskLevel: "LOW",
        classification: "TN",
        body: `Hi Max,

Sarah Johnson has invited you to join the Tech Startup workspace on Slack.

Workspace: Tech Startup
Invited by: Sarah Johnson (sarah@techstartup.com)

Join workspace:
www.slack.com/join/techstartup/invite-abc123

About this workspace:
Tech Startup is using Slack to collaborate and communicate.

Already have a Slack account?
Sign in: www.slack.com/signin

New to Slack?
Create account: www.slack.com/get-started

Questions about Slack?
Visit Help Center: www.slack.com/help

Slack Technologies, LLC
500 Howard Street
San Francisco, CA 94105, USA`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 11,
                patterns: [],
                evidence: [
                    "No urgency keywords",
                    "Standard invitation format",
                    "No suspicious requests"
                ]
            },
            owasp: {
                score: 8,
                patterns: [],
                evidence: [
                    "All URLs point to official slack.com domain",
                    "No suspicious links"
                ]
            },
            nist: {
                score: 7,
                patterns: [],
                evidence: [
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 10,
                patterns: [],
                evidence: [
                    "No sensitive data requests"
                ]
            },
            nessus: {
                score: 8,
                patterns: [],
                evidence: [
                    "No malware signatures"
                ]
            },
            openvas: {
                score: 9,
                patterns: [],
                evidence: [
                    "Legitimate workspace invitation"
                ]
            }
        },
        ollama: {
            summary: "This is a legitimate Slack workspace invitation. All authentication checks passed perfectly.",
            reasoning: "All indicators confirm legitimacy: (1) Perfect authentication. (2) Official domain - feedback@slack.com is correct. (3) All links point to official slack.com domain. (4) All frameworks scored very low (7-11%).",
            recommendations: [
                "Safe to read - this is a legitimate Slack invitation",
                "Join the workspace if you recognize the inviter",
                "No security action required"
            ]
        }
    },

    // Email 44-48: Final 5 English emails with varied classifications
    // Continuing with condensed but complete format to finish the dataset...

    // Email 44 - English HIGH TP - Chase Bank Security Alert
    {
        id: 44,
        subject: "Chase: Unusual activity on your account - Action required",
        from: "alerts@chase-security.com",
        language: "en",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Dear Chase Customer,

We detected unusual activity on your Chase account.

Account: Checking ****4567
Transaction: $3,250.00 - International Wire Transfer
Location: Moscow, Russia
Status: PENDING REVIEW

VERIFY NOW: http://chase-verify.com/secure

If this wasn't you, your account may be compromised.

Required actions:
1. Verify your identity
2. Confirm or dispute transaction
3. Update security settings

You must respond within 12 hours or the transaction will be processed.

Chase Bank
270 Park Avenue
New York, NY 10017, USA`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: { score: 92, patterns: ["Urgency keyword: Unusual activity", "Urgency keyword: 12 hours", "Suspicious URL"], evidence: ["Account compromise threat", "Foreign transaction (Russia)", "12-hour deadline", "Domain chase-security.com is suspicious"] },
            owasp: { score: 87, patterns: ["Banking credential harvesting"], evidence: ["Non-Chase domain", "Credential collection attempt"] },
            nist: { score: 91, patterns: ["Complete authentication failure"], evidence: ["Official Chase uses chase.com", "Sender spoofing confirmed"] },
            iso27001: { score: 89, patterns: ["Identity verification via email"], evidence: ["Banks don't verify via email links"] },
            nessus: { score: 85, patterns: ["Chase phishing pattern"], evidence: ["Known banking phishing campaign"] },
            openvas: { score: 88, patterns: ["Financial loss fear", "Foreign transaction threat"], evidence: ["Russia location creates fear", "Large transaction amount ($3,250)"] }
        },
        ollama: {
            summary: "This is a high-confidence phishing email impersonating Chase Bank. It uses fake fraud alerts to steal banking credentials.",
            reasoning: "Critical indicators: (1) Complete authentication failure. (2) Domain spoofing - chase-security.com is NOT official. (3) 12-hour deadline creates panic. (4) All frameworks scored 85%+.",
            recommendations: ["Delete immediately", "Do not click links", "Check actual account at chase.com", "Call Chase at 1-800-935-9935 if concerned"]
        }
    },

    // Email 45 - English LOW FN - Aggressive Marketing from Target
    {
        id: 45,
        subject: "FINAL HOURS: 60% OFF EVERYTHING ENDS TONIGHT!",
        from: "deals@target.com",
        language: "en",
        riskLevel: "LOW",
        classification: "FN",
        body: `Hi Max,

🔥 LAST CHANCE: 60% OFF EVERYTHING! 🔥

ENDS TONIGHT AT MIDNIGHT!

Shop now: www.target.com/deals

FREE SHIPPING + FREE RETURNS

Don't miss out!

Target Corporation
1000 Nicollet Mall
Minneapolis, MN 55403, USA`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: { score: 61, patterns: ["Urgency keyword: FINAL HOURS", "Urgency keyword: ENDS TONIGHT", "Large discount (60%)"], evidence: ["All caps subject line", "Midnight deadline", "However, domain is legitimate target.com"] },
            owasp: { score: 19, patterns: [], evidence: ["All URLs point to official target.com"] },
            nist: { score: 9, patterns: [], evidence: ["Perfect authentication"] },
            iso27001: { score: 25, patterns: ["Aggressive marketing"], evidence: ["No sensitive data requests"] },
            nessus: { score: 22, patterns: ["Aggressive marketing pattern"], evidence: ["Legitimate e-commerce"] },
            openvas: { score: 29, patterns: ["FOMO exploitation"], evidence: ["Legitimate but aggressive tactics"] }
        },
        ollama: {
            summary: "This is a FALSE NEGATIVE - a legitimate marketing email from Target that uses aggressive urgency tactics typical of phishing.",
            reasoning: "Classified as FALSE NEGATIVE: (1) Perfect authentication confirms legitimacy. (2) Official domain - deals@target.com is correct. (3) However, ML classifier scored 61% due to extreme urgency. (4) This is aggressive marketing, not phishing.",
            recommendations: ["This is legitimate Target marketing", "Visit target.com directly to verify sale", "Consider unsubscribing if too aggressive"]
        }
    },

    // Email 46 - English MEDIUM TP - Instagram Account Suspension
    {
        id: 46,
        subject: "Instagram: Your account has been suspended",
        from: "security@instagram-help.com",
        language: "en",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Hi Max,

Your Instagram account has been suspended due to violation of our Community Guidelines.

Account: @max_mustermann
Reason: Suspected spam activity
Status: SUSPENDED

APPEAL NOW: http://instagram-appeal.com/restore

If you don't appeal within 48 hours, your account will be permanently deleted.

All your:
• Photos and videos will be lost
• Followers will be removed
• Messages will be deleted

Appeal takes 2-3 minutes.

Instagram, LLC
1601 Willow Road
Menlo Park, CA 94025, USA`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: { score: 75, patterns: ["Urgency keyword: suspended", "Urgency keyword: 48 hours", "Urgency keyword: permanently deleted"], evidence: ["Account suspension creates panic", "48-hour deadline", "Domain instagram-help.com is suspicious"] },
            owasp: { score: 69, patterns: ["Credential harvesting"], evidence: ["Non-Instagram domain", "Account takeover attempt"] },
            nist: { score: 78, patterns: ["Authentication failure"], evidence: ["Official Instagram uses instagram.com", "Sender spoofing"] },
            iso27001: { score: 71, patterns: ["Account appeal via email"], evidence: ["Instagram handles appeals through app"] },
            nessus: { score: 66, patterns: ["Instagram suspension scam"], evidence: ["Known social media phishing"] },
            openvas: { score: 70, patterns: ["Content loss fear", "Social connection loss"], evidence: ["Threatens photo/video loss", "Follower removal threat"] }
        },
        ollama: {
            summary: "This is a medium-risk phishing email impersonating Instagram. It uses fake account suspension to steal credentials.",
            reasoning: "Multiple indicators: (1) Complete authentication failure. (2) Domain spoofing - instagram-help.com is NOT official. (3) 48-hour deadline with deletion threat. (4) Framework scores in 66-78% range.",
            recommendations: ["Delete this email", "Do not click links", "Check actual account status in Instagram app", "Instagram handles appeals through the app, not email"]
        }
    },

    // Email 47 - English LOW TN - Zoom Meeting Invitation
    {
        id: 47,
        subject: "You're invited to a Zoom meeting",
        from: "no-reply@zoom.us",
        language: "en",
        riskLevel: "LOW",
        classification: "TN",
        body: `Hi Max,

Sarah Johnson is inviting you to a scheduled Zoom meeting.

Topic: DefenderSim Project Review
Time: February 12, 2026 10:00 AM EST
Duration: 1 hour

Join Zoom Meeting:
www.zoom.us/j/1234567890?pwd=abc123

Meeting ID: 123 456 7890
Passcode: 987654

Join by phone: +1 646 558 8656

Zoom Video Communications, Inc.
55 Almaden Blvd, Suite 600
San Jose, CA 95113, USA`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: { score: 13, patterns: [], evidence: ["No urgency keywords", "Standard meeting invitation"] },
            owasp: { score: 8, patterns: [], evidence: ["All URLs point to official zoom.us"] },
            nist: { score: 7, patterns: [], evidence: ["Perfect authentication"] },
            iso27001: { score: 10, patterns: [], evidence: ["No sensitive data requests"] },
            nessus: { score: 8, patterns: [], evidence: ["No malware"] },
            openvas: { score: 9, patterns: [], evidence: ["Legitimate meeting invitation"] }
        },
        ollama: {
            summary: "This is a legitimate Zoom meeting invitation. All authentication checks passed perfectly.",
            reasoning: "All indicators confirm legitimacy: (1) Perfect authentication. (2) Official domain - no-reply@zoom.us is correct. (3) All frameworks scored very low (7-13%).",
            recommendations: ["Safe to read", "Join meeting if you recognize the host", "No security action required"]
        }
    },

    // Email 48 - English HIGH TP - Coinbase Account Alert
    {
        id: 48,
        subject: "Coinbase: Unusual withdrawal detected - Verify immediately",
        from: "security@coinbase-alerts.com",
        language: "en",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Dear Coinbase User,

We detected an unusual cryptocurrency withdrawal from your account.

Amount: 2.5 BTC ($125,000 USD)
Destination: External Wallet
Status: PENDING VERIFICATION

VERIFY NOW: http://coinbase-secure.com/verify

If this wasn't you, your account may be compromised.

You must verify within 2 hours or the withdrawal will be processed.

Required:
• Account credentials
• 2FA code
• Government ID

Coinbase, Inc.
100 Pine Street
San Francisco, CA 94111, USA`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: { score: 94, patterns: ["Urgency keyword: Unusual withdrawal", "Urgency keyword: 2 hours", "Urgency keyword: compromised"], evidence: ["Large cryptocurrency amount", "2-hour deadline", "Domain coinbase-alerts.com is suspicious"] },
            owasp: { score: 90, patterns: ["Credential harvesting", "2FA code theft"], evidence: ["Non-Coinbase domain", "Requests 2FA code - major red flag"] },
            nist: { score: 93, patterns: ["Authentication failure"], evidence: ["Official Coinbase uses coinbase.com", "Sender spoofing"] },
            iso27001: { score: 91, patterns: ["2FA code request", "ID request via email"], evidence: ["Requesting 2FA code via email is NEVER legitimate"] },
            nessus: { score: 88, patterns: ["Cryptocurrency phishing"], evidence: ["Known crypto exchange phishing"] },
            openvas: { score: 90, patterns: ["Financial loss fear", "Large amount threat"], evidence: ["$125,000 creates extreme panic", "2-hour deadline"] }
        },
        ollama: {
            summary: "This is a CRITICAL phishing email impersonating Coinbase. It uses fake cryptocurrency withdrawal alerts to steal credentials and 2FA codes.",
            reasoning: "CRITICAL indicators: (1) Complete authentication failure. (2) Domain spoofing - coinbase-alerts.com is NOT official. (3) Requests 2FA code - NEVER legitimate. (4) Large amount ($125,000) creates panic. (5) All frameworks scored 88%+.",
            recommendations: ["Delete immediately - CRITICAL SCAM", "NEVER provide 2FA codes via email", "Check actual account at coinbase.com", "Enable withdrawal whitelist if available", "Contact Coinbase support immediately if concerned"]
        }
    }
];

    // FRENCH EMAILS (49-60) - 12 emails total

    // Email 49 - French HIGH TP - Crédit Agricole Account Alert
    {
        id: 49,
        subject: "Crédit Agricole: Activité suspecte détectée sur votre compte",
        from: "securite@creditagricole-alerte.fr",
        language: "fr",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Cher client,

Nous avons détecté une activité suspecte sur votre compte Crédit Agricole.

Compte: Compte Courant ****2345
Transaction: 3 450,00 € - Virement international
Destination: Roumanie
Statut: EN ATTENTE DE VÉRIFICATION

VÉRIFIEZ MAINTENANT: http://creditagricole-verif.fr/securite

Si ce n'était pas vous, votre compte pourrait être compromis.

Actions requises:
1. Vérifiez votre identité
2. Confirmez ou contestez la transaction
3. Mettez à jour vos paramètres de sécurité

Vous devez répondre dans les 24 heures ou la transaction sera traitée.

Informations requises:
• Numéro de compte complet
• Code confidentiel
• Numéro de carte bancaire
• Date de naissance

Conséquences si vous ne vérifiez pas:
• La transaction sera effectuée
• Votre compte pourrait être compromis
• Perte financière possible

Protégez votre compte maintenant.

Crédit Agricole S.A.
12 Place des États-Unis
92127 Montrouge, France

Ceci est une notification de sécurité automatisée.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 93,
                patterns: [
                    "Urgency keyword: suspecte",
                    "Urgency keyword: EN ATTENTE",
                    "Urgency keyword: compromis",
                    "Urgency keyword: 24 heures",
                    "Suspicious URL detected",
                    "Large transaction amount",
                    "Sensitive data request"
                ],
                evidence: [
                    "Suspicious activity creates panic",
                    "Large amount (€3,450) creates concern",
                    "Foreign destination (Romania) increases fear",
                    "24-hour deadline creates urgency",
                    "Domain creditagricole-alerte.fr is suspicious",
                    "Requests extremely sensitive information (account number, PIN, card number)",
                    "Threatens financial loss"
                ]
            },
            owasp: {
                score: 91,
                patterns: [
                    "Banking credential harvesting",
                    "PIN collection attempt",
                    "Card number theft",
                    "Identity theft"
                ],
                evidence: [
                    "Non-Crédit Agricole domain with verification path",
                    "URL designed to collect complete banking credentials",
                    "Requests PIN - NEVER legitimate",
                    "Requests card number and personal information",
                    "HTTP instead of HTTPS for banking"
                ]
            },
            nist: {
                score: 94,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Financial institution spoofing"
                ],
                evidence: [
                    "Complete authentication failure",
                    "Official Crédit Agricole uses credit-agricole.fr",
                    "creditagricole-alerte.fr is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 92,
                patterns: [
                    "PIN request via email",
                    "Card number request",
                    "Complete credential collection",
                    "Banking security violation"
                ],
                evidence: [
                    "Requests PIN via email - NEVER legitimate",
                    "Asks for complete card number",
                    "Requests date of birth for identity theft",
                    "Banks NEVER request PINs via email",
                    "Violates all banking security standards"
                ]
            },
            nessus: {
                score: 89,
                patterns: [
                    "French banking phishing pattern",
                    "Account takeover attempt"
                ],
                evidence: [
                    "Matches known French banking phishing campaigns",
                    "Transaction verification theme is common",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 91,
                patterns: [
                    "Financial loss fear",
                    "Foreign transaction threat",
                    "Account compromise threat",
                    "Complete identity theft attempt"
                ],
                evidence: [
                    "Large transaction amount (€3,450) creates panic",
                    "Romania destination creates fear (Eastern Europe)",
                    "Threatens account compromise and financial loss",
                    "24-hour deadline creates urgency",
                    "Requests complete identity theft package"
                ]
            }
        },
        ollama: {
            summary: "Il s'agit d'un email de phishing à haut risque usurpant l'identité du Crédit Agricole. Il utilise de fausses alertes de transactions suspectes pour voler les identifiants bancaires complets, y compris les codes PIN.",
            reasoning: "Indicateurs critiques de phishing: (1) Échec complet de l'authentification - tous les contrôles ont échoué, confirmant l'usurpation d'identité. (2) Usurpation de domaine - creditagricole-alerte.fr et creditagricole-verif.fr ne sont PAS des domaines officiels du Crédit Agricole (officiel: credit-agricole.fr). (3) Demandes de données extrêmes - demander le numéro de compte complet, le code PIN, le numéro de carte bancaire par email n'est JAMAIS légitime. (4) Violation de processus - les banques ne demandent JAMAIS les codes PIN par email. (5) Menaces multiples - traitement de la transaction, compromission du compte, perte financière. (6) Tous les frameworks ont obtenu des scores de 89%+. (7) Le montant spécifique (€3,450) et la destination (Roumanie) sont conçus pour créer la panique. (8) Le Crédit Agricole gère les alertes de fraude exclusivement via l'application mobile ou le site web sécurisé. Cet email pourrait conduire à une prise de contrôle complète du compte et à une fraude financière.",
            recommendations: [
                "Supprimez cet email immédiatement - c'est une arnaque de phishing DANGEREUSE",
                "Ne cliquez sur aucun lien et ne fournissez AUCUNE information",
                "Ne JAMAIS fournir votre code PIN ou mot de passe par email",
                "Les banques ne demandent JAMAIS les codes PIN par email",
                "Vérifiez votre compte réel sur credit-agricole.fr ou appelez le 09 69 39 69 00",
                "Si vous avez cliqué sur le lien et saisi des informations, prenez des mesures IMMÉDIATES: (1) Contactez le Crédit Agricole immédiatement, (2) Changez vos mots de passe, (3) Faites opposition sur vos cartes, (4) Surveillez vos transactions",
                "Activez les alertes de transaction pour toutes les opérations",
                "Signalez cette arnaque au Crédit Agricole et à Pharos (internet-signalement.gouv.fr)",
                "Le phishing bancaire est extrêmement dangereux et peut conduire à une prise de contrôle complète du compte",
                "Les alertes de fraude légitimes du Crédit Agricole arrivent via l'application mobile ou le site web sécurisé"
            ]
        }
    },

    // Email 50 - French MEDIUM TP - La Poste Delivery Notification
    {
        id: 50,
        subject: "La Poste: Votre colis est en attente de livraison",
        from: "livraison@laposte-suivi.fr",
        language: "fr",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Bonjour,

Votre colis La Poste est en attente de livraison.

Numéro de suivi: LP123456789FR
Expéditeur: Amazon
Statut: En attente de paiement

PAYER LES FRAIS: http://laposte-livraison.fr/paiement?colis=LP123456789

Frais de livraison impayés: 2,99 €

Votre colis sera retourné à l'expéditeur si vous ne payez pas dans les 48 heures.

Détails du colis:
• Poids: 1,2 kg
• Dimensions: 30x20x10 cm
• Valeur déclarée: 89,00 €

Payez maintenant pour recevoir votre colis.

La Poste
9 Rue du Colonel Pierre Avia
75015 Paris, France

Ceci est une notification automatique.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 71,
                patterns: [
                    "Urgency keyword: en attente",
                    "Urgency keyword: 48 heures",
                    "Urgency keyword: retourné",
                    "Suspicious URL detected",
                    "Payment request"
                ],
                evidence: [
                    "Package waiting creates concern",
                    "48-hour deadline creates urgency",
                    "Domain laposte-suivi.fr is suspicious",
                    "Threatens package return",
                    "Small payment (€2.99) appears reasonable"
                ]
            },
            owasp: {
                score: 66,
                patterns: [
                    "Payment information harvesting",
                    "Delivery scam"
                ],
                evidence: [
                    "Non-La Poste domain with payment path",
                    "URL designed to collect payment information",
                    "Package parameter suggests tracking"
                ]
            },
            nist: {
                score: 75,
                patterns: [
                    "DMARC authentication failed",
                    "SPF authentication failed",
                    "DKIM authentication failed",
                    "Domain spoofing"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official La Poste uses laposte.fr",
                    "laposte-suivi.fr is fraudulent domain",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 68,
                patterns: [
                    "Payment request via email link"
                ],
                evidence: [
                    "Requests payment via email link",
                    "La Poste handles payments through official website",
                    "Violates payment security practices"
                ]
            },
            nessus: {
                score: 63,
                patterns: [
                    "Delivery fee scam",
                    "Package notification phishing"
                ],
                evidence: [
                    "Matches known delivery phishing campaigns",
                    "Unpaid delivery fee theme is common",
                    "Similar attacks documented"
                ]
            },
            openvas: {
                score: 67,
                patterns: [
                    "Package loss fear",
                    "Small payment exploitation",
                    "Return threat"
                ],
                evidence: [
                    "Exploits fear of losing package",
                    "Small amount (€2.99) reduces suspicion",
                    "48-hour deadline creates urgency",
                    "Threatens package return to sender"
                ]
            }
        },
        ollama: {
            summary: "Il s'agit d'un email de phishing à risque moyen usurpant l'identité de La Poste. Il utilise de fausses notifications de colis en attente pour voler les informations de paiement.",
            reasoning: "Plusieurs indicateurs suggèrent du phishing: (1) Échec complet de l'authentification - tous les contrôles ont échoué. (2) Usurpation de domaine - laposte-suivi.fr et laposte-livraison.fr ne sont PAS des domaines officiels de La Poste (officiel: laposte.fr). (3) Demande de paiement - redirige vers une fausse page de paiement. (4) Urgence - délai de 48 heures avec menace de retour du colis. (5) Les scores des frameworks sont dans la fourchette 63-75%, indiquant un risque moyen-élevé. (6) Le petit montant (€2,99) est conçu pour paraître raisonnable et réduire la suspicion. (7) La Poste envoie des notifications de colis via l'application mobile et le site web officiel, jamais via des liens de paiement par email.",
            recommendations: [
                "Supprimez cet email - c'est une arnaque de phishing",
                "Ne cliquez sur aucun lien et ne fournissez pas d'informations de paiement",
                "Vérifiez le suivi réel de votre colis sur laposte.fr",
                "La Poste ne demande jamais de paiement de frais de livraison par email",
                "Si vous attendez un colis, suivez-le via l'application La Poste ou laposte.fr",
                "Si vous avez cliqué et saisi des informations de paiement, contactez votre banque immédiatement",
                "Surveillez vos relevés bancaires pour des transactions non autorisées",
                "Signalez cette arnaque à La Poste et à Pharos",
                "Les arnaques aux colis sont très courantes, surtout après les achats en ligne",
                "Les notifications légitimes de La Poste arrivent via l'application mobile ou le site web"
            ]
        }
    },

    // Email 51 - French LOW TN - OVH Server Maintenance
    {
        id: 51,
        subject: "OVHcloud: Maintenance programmée sur votre serveur",
        from: "noreply@ovh.com",
        language: "fr",
        riskLevel: "LOW",
        classification: "TN",
        body: `Bonjour,

Une maintenance programmée aura lieu sur votre serveur OVHcloud.

Serveur: vps-123456.vps.ovh.net
Date: 15 février 2026
Heure: 02:00 - 04:00 CET
Durée estimée: 2 heures

Raison: Mise à jour de sécurité du système

Impact:
• Votre serveur sera temporairement indisponible
• Les services hébergés seront inaccessibles
• Aucune action requise de votre part

La maintenance sera effectuée automatiquement.

Gérer votre serveur:
www.ovh.com/manager/

Assistance OVHcloud:
www.ovh.com/fr/support/

OVHcloud
2 rue Kellermann
59100 Roubaix, France

Ceci est une notification automatique.`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 15,
                patterns: [],
                evidence: [
                    "No urgency keywords",
                    "Standard maintenance notification",
                    "Professional technical language",
                    "No suspicious requests"
                ]
            },
            owasp: {
                score: 9,
                patterns: [],
                evidence: [
                    "All URLs point to official ovh.com domain",
                    "No suspicious links",
                    "Standard server maintenance format"
                ]
            },
            nist: {
                score: 7,
                patterns: [],
                evidence: [
                    "DMARC authentication passed",
                    "SPF authentication passed",
                    "DKIM authentication passed",
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 11,
                patterns: [],
                evidence: [
                    "No sensitive data requests",
                    "Standard maintenance communication",
                    "Appropriate notification procedures"
                ]
            },
            nessus: {
                score: 8,
                patterns: [],
                evidence: [
                    "No malware signatures",
                    "Clean maintenance notification"
                ]
            },
            openvas: {
                score: 10,
                patterns: [],
                evidence: [
                    "No vulnerability indicators",
                    "Legitimate hosting provider notification"
                ]
            }
        },
        ollama: {
            summary: "Il s'agit d'une notification de maintenance légitime d'OVHcloud. Tous les contrôles d'authentification sont passés parfaitement, et l'email suit les pratiques standard de notification de maintenance.",
            reasoning: "Tous les indicateurs confirment la légitimité: (1) Authentification parfaite - DMARC, SPF, DKIM tous passés. (2) Domaine officiel - noreply@ovh.com est correct. (3) Format standard avec détails du serveur, date/heure de maintenance, et impact. (4) Tous les liens pointent vers le domaine officiel ovh.com. (5) Tous les frameworks ont obtenu des scores très faibles (7-15%). (6) Aucune tactique d'urgence, aucune demande de paiement, aucun élément suspect. (7) OVHcloud envoie régulièrement des notifications de maintenance planifiée.",
            recommendations: [
                "Sûr à lire - c'est une notification de maintenance légitime d'OVHcloud",
                "Notez la date et l'heure de la maintenance (15 février 2026, 02:00-04:00 CET)",
                "Votre serveur sera indisponible pendant environ 2 heures",
                "Aucune action requise de votre part",
                "Informez vos utilisateurs si nécessaire",
                "Aucune action de sécurité requise"
            ]
        }
    },

    // Email 52 - French MEDIUM TP - BNP Paribas Security Update
    {
        id: 52,
        subject: "BNP Paribas: Mise à jour de sécurité requise",
        from: "securite@bnpparibas-banque.fr",
        language: "fr",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Cher client,

Une mise à jour de sécurité est requise pour votre compte BNP Paribas.

Compte: Compte Chèques ****6789
Statut: Mise à jour requise
Date limite: 13 février 2026

METTRE À JOUR: http://bnpparibas-securite.fr/update

Nouvelles mesures de sécurité:
• Authentification renforcée
• Vérification en deux étapes
• Protection contre la fraude

Si vous ne mettez pas à jour avant la date limite:
• Accès en ligne limité
• Transactions bloquées
• Services bancaires restreints

La mise à jour prend 3-5 minutes.

BNP Paribas
16 Boulevard des Italiens
75009 Paris, France

Ceci est une notification de sécurité automatisée.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 74,
                patterns: [
                    "Urgency keyword: requise",
                    "Urgency keyword: Date limite",
                    "Urgency keyword: bloquées",
                    "Suspicious URL detected"
                ],
                evidence: [
                    "Security update requirement creates urgency",
                    "Deadline creates pressure",
                    "Domain bnpparibas-banque.fr is suspicious",
                    "Threatens account restrictions"
                ]
            },
            owasp: {
                score: 68,
                patterns: [
                    "Credential harvesting attempt",
                    "Security update scam"
                ],
                evidence: [
                    "Non-BNP Paribas domain with update path",
                    "URL designed to collect credentials"
                ]
            },
            nist: {
                score: 77,
                patterns: [
                    "Authentication failure",
                    "Domain spoofing"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official BNP Paribas uses bnpparibas.fr",
                    "Sender spoofing confirmed"
                ]
            },
            iso27001: {
                score: 71,
                patterns: [
                    "Security update via email link"
                ],
                evidence: [
                    "Requests security update via email",
                    "Banks handle updates through official website"
                ]
            },
            nessus: {
                score: 66,
                patterns: [
                    "Banking security update scam"
                ],
                evidence: [
                    "Known French banking phishing pattern"
                ]
            },
            openvas: {
                score: 70,
                patterns: [
                    "Service restriction threat",
                    "Account limitation fear"
                ],
                evidence: [
                    "Threatens limited access and blocked transactions",
                    "Deadline creates urgency"
                ]
            }
        },
        ollama: {
            summary: "Il s'agit d'un email de phishing à risque moyen usurpant l'identité de BNP Paribas. Il utilise de fausses mises à jour de sécurité pour voler les identifiants bancaires.",
            reasoning: "Plusieurs indicateurs suggèrent du phishing: (1) Échec complet de l'authentification. (2) Usurpation de domaine - bnpparibas-banque.fr n'est PAS officiel. (3) Demande de mise à jour via email. (4) Menaces de restrictions de compte. (5) Scores des frameworks dans la fourchette 66-77%.",
            recommendations: [
                "Supprimez cet email - c'est du phishing",
                "Ne cliquez sur aucun lien",
                "Vérifiez votre compte sur bnpparibas.fr",
                "BNP Paribas gère les mises à jour via le site officiel",
                "Signalez cette arnaque à BNP Paribas"
            ]
        }
    },

    // Email 53 - French HIGH TP - Orange Mobile Bill Scam
    {
        id: 53,
        subject: "Orange: Votre facture mobile de 245,90 € est disponible",
        from: "facture@orange-mobile.fr",
        language: "fr",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Bonjour,

Votre nouvelle facture Orange est disponible.

Numéro de ligne: 06 12 34 56 78
Montant: 245,90 €
Date d'échéance: 12 février 2026

CONSULTER LA FACTURE: http://orange-factures.fr/voir?id=245

Détails de la facture:
• Abonnement mobile: 19,99 €
• Hors forfait: 225,91 €
• Total TTC: 245,90 €

Attention: Des frais de hors forfait inhabituels ont été détectés.

Si vous contestez ces frais, cliquez ici:
http://orange-factures.fr/contester

Le paiement sera prélevé automatiquement le 12 février 2026.

Orange S.A.
78 rue Olivier de Serres
75015 Paris, France

Ceci est une notification automatique.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 88,
                patterns: [
                    "Urgency keyword: Attention",
                    "Urgency keyword: inhabituels",
                    "Suspicious URL detected",
                    "High bill amount",
                    "Automatic payment threat"
                ],
                evidence: [
                    "Unusually high bill (€245.90) creates panic",
                    "Out-of-bundle charges (€225.91) appear suspicious",
                    "Domain orange-mobile.fr is suspicious",
                    "Automatic payment creates urgency",
                    "Dispute option is a trap"
                ]
            },
            owasp: {
                score: 83,
                patterns: [
                    "Payment information harvesting",
                    "Billing scam"
                ],
                evidence: [
                    "Non-Orange domain with billing path",
                    "URL designed to collect payment information",
                    "Dispute link is credential harvesting trap"
                ]
            },
            nist: {
                score: 90,
                patterns: [
                    "Authentication failure",
                    "Telecom provider spoofing"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Orange uses orange.fr",
                    "orange-mobile.fr is fraudulent domain"
                ]
            },
            iso27001: {
                score: 85,
                patterns: [
                    "Bill payment via email link",
                    "Dispute handling through email"
                ],
                evidence: [
                    "Requests bill viewing via email link",
                    "Orange handles billing through official website"
                ]
            },
            nessus: {
                score: 81,
                patterns: [
                    "Telecom billing scam",
                    "High bill shock tactic"
                ],
                evidence: [
                    "Known French telecom phishing pattern",
                    "High bill amount is common scare tactic"
                ]
            },
            openvas: {
                score: 84,
                patterns: [
                    "Financial shock manipulation",
                    "Automatic payment threat",
                    "Dispute trap"
                ],
                evidence: [
                    "High bill amount (€245.90) creates immediate panic",
                    "Out-of-bundle charges (€225.91) appear suspicious",
                    "Automatic payment threat creates urgency",
                    "Dispute option is designed to harvest credentials"
                ]
            }
        },
        ollama: {
            summary: "Il s'agit d'un email de phishing à haut risque usurpant l'identité d'Orange. Il utilise de fausses factures avec des montants élevés pour voler les informations de paiement et les identifiants de compte.",
            reasoning: "Indicateurs critiques de phishing: (1) Échec complet de l'authentification. (2) Usurpation de domaine - orange-mobile.fr et orange-factures.fr ne sont PAS des domaines officiels d'Orange (officiel: orange.fr). (3) Montant élevé - €245,90 avec €225,91 de hors forfait crée la panique. (4) Menace de prélèvement automatique. (5) L'option de contestation est un piège pour voler les identifiants. (6) Tous les frameworks ont obtenu des scores de 81%+. (7) Orange envoie les factures via l'espace client sur orange.fr, jamais via des liens externes. (8) Le montant élevé inhabituel est conçu pour créer un choc financier et pousser à l'action immédiate.",
            recommendations: [
                "Supprimez cet email immédiatement - c'est une arnaque de phishing",
                "Ne cliquez sur AUCUN lien (ni consultation ni contestation)",
                "Vérifiez votre facture réelle sur orange.fr ou l'application Orange",
                "Orange envoie les factures via l'espace client, jamais par liens externes",
                "Si vous avez cliqué et saisi des informations, contactez Orange immédiatement au 3900",
                "Surveillez vos prélèvements bancaires",
                "Signalez cette arnaque à Orange et à Pharos",
                "Les arnaques aux factures élevées sont courantes pour créer la panique",
                "Vérifiez toujours les factures via les canaux officiels avant de payer"
            ]
        }
    },

    // Email 54 - French LOW TN - SNCF Train Ticket Confirmation
    {
        id: 54,
        subject: "SNCF: Confirmation de votre billet de train",
        from: "noreply@sncf.com",
        language: "fr",
        riskLevel: "LOW",
        classification: "TN",
        body: `Bonjour Max Mustermann,

Votre billet de train SNCF a été confirmé.

Numéro de réservation: SNCF123456789
Date de voyage: 14 février 2026

Détails du voyage:
Départ: Paris Gare de Lyon - 10:30
Arrivée: Lyon Part-Dieu - 12:30
Train: TGV 6601
Classe: 2ème classe
Place: Voiture 12, Place 45

Prix: 45,00 €
Mode de paiement: Carte Visa ****1234

Télécharger votre billet:
www.sncf-connect.com/mes-voyages

Gérer votre réservation:
www.sncf-connect.com/gerer-reservation

Service client SNCF:
www.sncf-connect.com/aide

SNCF Voyageurs
2 Place de la Défense
92053 Paris La Défense, France

Ceci est une confirmation automatique.`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 13,
                patterns: [],
                evidence: [
                    "No urgency keywords",
                    "Standard ticket confirmation",
                    "Professional travel language"
                ]
            },
            owasp: {
                score: 8,
                patterns: [],
                evidence: [
                    "All URLs point to official sncf-connect.com"
                ]
            },
            nist: {
                score: 7,
                patterns: [],
                evidence: [
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 10,
                patterns: [],
                evidence: [
                    "No sensitive data requests"
                ]
            },
            nessus: {
                score: 8,
                patterns: [],
                evidence: [
                    "No malware"
                ]
            },
            openvas: {
                score: 9,
                patterns: [],
                evidence: [
                    "Legitimate ticket confirmation"
                ]
            }
        },
        ollama: {
            summary: "Il s'agit d'une confirmation de billet de train légitime de la SNCF. Tous les contrôles d'authentification sont passés parfaitement.",
            reasoning: "Tous les indicateurs confirment la légitimité: (1) Authentification parfaite. (2) Domaine officiel - noreply@sncf.com est correct. (3) Tous les liens pointent vers sncf-connect.com. (4) Tous les frameworks ont obtenu des scores très faibles (7-13%).",
            recommendations: [
                "Sûr à lire - c'est une confirmation légitime de la SNCF",
                "Téléchargez votre billet avant le voyage",
                "Conservez cet email pour vos dossiers",
                "Aucune action de sécurité requise"
            ]
        }
    },

    // Email 55 - French MEDIUM TP - Ameli Social Security Scam
    {
        id: 55,
        subject: "Ameli: Remboursement de 127,50 € en attente",
        from: "remboursement@ameli-assurance.fr",
        language: "fr",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Bonjour,

Vous avez un remboursement en attente de l'Assurance Maladie.

Montant: 127,50 €
Type: Frais médicaux
Statut: En attente de validation

VALIDER LE REMBOURSEMENT: http://ameli-rembours.fr/valider

Pour recevoir votre remboursement, veuillez confirmer vos coordonnées bancaires.

Informations requises:
• Numéro de sécurité sociale
• RIB (IBAN et BIC)
• Carte Vitale (numéro)

Le remboursement sera effectué sous 48 heures après validation.

Si vous ne validez pas dans les 7 jours, le remboursement sera annulé.

Assurance Maladie - Ameli
50 Avenue du Professeur André Lemierre
75020 Paris, France

Ceci est une notification automatique.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 72,
                patterns: [
                    "Urgency keyword: en attente",
                    "Urgency keyword: 7 jours",
                    "Urgency keyword: annulé",
                    "Suspicious URL detected",
                    "Financial reward (refund)"
                ],
                evidence: [
                    "Refund creates positive incentive",
                    "Specific amount (€127.50) appears legitimate",
                    "7-day deadline creates urgency",
                    "Domain ameli-assurance.fr is suspicious",
                    "Requests sensitive information (social security number, bank details)"
                ]
            },
            owasp: {
                score: 67,
                patterns: [
                    "Banking information harvesting",
                    "Social security number collection",
                    "Identity theft attempt"
                ],
                evidence: [
                    "Non-Ameli domain with refund path",
                    "Requests social security number",
                    "Asks for complete bank details (IBAN, BIC)",
                    "Carte Vitale number request"
                ]
            },
            nist: {
                score: 76,
                patterns: [
                    "Authentication failure",
                    "Government service spoofing"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Ameli uses ameli.fr",
                    "ameli-assurance.fr is fraudulent domain"
                ]
            },
            iso27001: {
                score: 70,
                patterns: [
                    "Social security number via email",
                    "Bank details via email link"
                ],
                evidence: [
                    "Requests social security number via email",
                    "Ameli never requests bank details via email"
                ]
            },
            nessus: {
                score: 65,
                patterns: [
                    "Social security refund scam",
                    "Ameli impersonation"
                ],
                evidence: [
                    "Known French social security phishing pattern"
                ]
            },
            openvas: {
                score: 69,
                patterns: [
                    "Financial reward manipulation",
                    "Government authority exploitation",
                    "Refund cancellation threat"
                ],
                evidence: [
                    "Uses financial reward to motivate action",
                    "Exploits government authority for trust",
                    "7-day deadline with cancellation threat"
                ]
            }
        },
        ollama: {
            summary: "Il s'agit d'un email de phishing à risque moyen usurpant l'identité d'Ameli (Assurance Maladie). Il utilise de faux remboursements pour voler les numéros de sécurité sociale et les coordonnées bancaires.",
            reasoning: "Plusieurs indicateurs suggèrent du phishing: (1) Échec complet de l'authentification. (2) Usurpation de domaine - ameli-assurance.fr et ameli-rembours.fr ne sont PAS des domaines officiels d'Ameli (officiel: ameli.fr). (3) Demandes de données sensibles - numéro de sécurité sociale, RIB complet, numéro de Carte Vitale. (4) Urgence - délai de 7 jours avec menace d'annulation. (5) Scores des frameworks dans la fourchette 65-76%. (6) Ameli ne demande JAMAIS les coordonnées bancaires par email. (7) Les remboursements Ameli sont automatiques et ne nécessitent aucune validation.",
            recommendations: [
                "Supprimez cet email - c'est du phishing",
                "Ne cliquez sur aucun lien",
                "Ne fournissez JAMAIS votre numéro de sécurité sociale par email",
                "Ameli ne demande jamais de coordonnées bancaires par email",
                "Vérifiez vos remboursements réels sur ameli.fr",
                "Les remboursements Ameli sont automatiques",
                "Signalez cette arnaque à Ameli et à Pharos"
            ]
        }
    },

    // Email 56 - French LOW FP - Urgent Government Tax Notice
    {
        id: 56,
        subject: "URGENT: Impots.gouv.fr - Déclaration de revenus à compléter",
        from: "noreply@dgfip.finances.gouv.fr",
        language: "fr",
        riskLevel: "LOW",
        classification: "FP",
        body: `Madame, Monsieur,

Votre déclaration de revenus 2025 nécessite des informations complémentaires.

Numéro fiscal: 1234567890123
Date limite: 28 février 2026

COMPLÉTER VOTRE DÉCLARATION:
www.impots.gouv.fr/portail/

Informations manquantes:
• Revenus fonciers
• Plus-values mobilières
• Charges déductibles

En cas de non-réponse avant la date limite, votre déclaration sera traitée en l'état et pourrait entraîner une régularisation fiscale.

Accéder à votre espace particulier:
www.impots.gouv.fr/portail/particulier

Assistance:
www.impots.gouv.fr/portail/contact

Direction Générale des Finances Publiques
139 Rue de Bercy
75012 Paris, France

Ceci est un message automatique du service des impôts.`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 58,
                patterns: [
                    "Urgency keyword: URGENT",
                    "Urgency keyword: Date limite",
                    "Urgency keyword: régularisation fiscale",
                    "Government authority"
                ],
                evidence: [
                    "Subject line in all caps with URGENT",
                    "Tax deadline creates urgency",
                    "Threatens tax regularization",
                    "However, domain is legitimate dgfip.finances.gouv.fr",
                    "All links point to official impots.gouv.fr"
                ]
            },
            owasp: {
                score: 17,
                patterns: [],
                evidence: [
                    "All URLs point to official impots.gouv.fr domain"
                ]
            },
            nist: {
                score: 10,
                patterns: [],
                evidence: [
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 24,
                patterns: [
                    "Urgent tax action required"
                ],
                evidence: [
                    "This is legitimate government communication"
                ]
            },
            nessus: {
                score: 20,
                patterns: [
                    "Urgent government notice pattern"
                ],
                evidence: [
                    "This is a legitimate tax notification"
                ]
            },
            openvas: {
                score: 28,
                patterns: [
                    "Tax penalty threat (legitimate)",
                    "Urgency tactics (legitimate reason)"
                ],
                evidence: [
                    "Uses urgency language typical of phishing",
                    "However, tax deadlines require urgent action",
                    "This is legitimate government communication"
                ]
            }
        },
        ollama: {
            summary: "Il s'agit d'un FAUX POSITIF - une notification fiscale légitime de la Direction Générale des Finances Publiques. Bien qu'elle utilise un langage urgent typique du phishing, c'est une communication gouvernementale authentique.",
            reasoning: "Classé comme FAUX POSITIF car il semble suspect mais est en réalité légitime: (1) Authentification parfaite - DMARC, SPF, DKIM tous passés. (2) Domaine officiel - noreply@dgfip.finances.gouv.fr est correct pour les impôts français. (3) Tous les liens pointent vers le domaine légitime impots.gouv.fr. (4) Cependant, le classificateur ML a obtenu 58% en raison du langage d'urgence extrême: 'URGENT', 'Date limite', 'régularisation fiscale'. (5) Les notifications fiscales nécessitent RÉELLEMENT une action urgente, rendant cette urgence légitime. (6) La DGFiP envoie des notifications officielles via dgfip.finances.gouv.fr. (7) Cela démontre que les notifications gouvernementales légitimes peuvent déclencher la détection de phishing lorsqu'elles utilisent un langage urgent, ce qui est nécessaire pour les échéances fiscales.",
            recommendations: [
                "Ceci est une notification fiscale légitime de la DGFiP",
                "L'urgence est justifiée - les déclarations fiscales ont des délais stricts",
                "Connectez-vous à impots.gouv.fr pour compléter votre déclaration",
                "Utilisez uniquement le site officiel impots.gouv.fr",
                "En cas de doute, contactez votre centre des impôts",
                "Respectez la date limite pour éviter une régularisation",
                "Cet email démontre pourquoi la vérification est importante: les communications gouvernementales légitimes peuvent sembler urgentes"
            ]
        }
    },

    // Email 57 - French HIGH TP - Société Générale Account Lockout
    {
        id: 57,
        subject: "Société Générale: Votre compte a été bloqué",
        from: "securite@societegenerale-banque.fr",
        language: "fr",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Cher client,

Votre compte Société Générale a été temporairement bloqué pour des raisons de sécurité.

Compte: Compte Courant ****4321
Raison: Activité suspecte détectée
Statut: BLOQUÉ

DÉBLOQUER VOTRE COMPTE: http://societegenerale-secure.fr/debloquer

Activité suspecte détectée:
• Tentative de connexion depuis l'étranger
• Modification des coordonnées bancaires
• Virement inhabituel

Pour débloquer votre compte, vous devez:
1. Vérifier votre identité
2. Confirmer vos informations bancaires
3. Réinitialiser votre mot de passe

Informations requises:
• Numéro de compte complet
• Code secret
• Numéro de carte bancaire et code CVV
• Date de naissance

Si vous ne débloquez pas dans les 24 heures:
• Votre compte sera définitivement fermé
• Vos fonds seront gelés pendant 90 jours
• Vous devrez ouvrir un nouveau compte

Débloquez votre compte maintenant.

Société Générale
29 Boulevard Haussmann
75009 Paris, France

Ceci est une alerte de sécurité automatisée.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 96,
                patterns: [
                    "Urgency keyword: bloqué",
                    "Urgency keyword: BLOQUÉ",
                    "Urgency keyword: 24 heures",
                    "Urgency keyword: définitivement fermé",
                    "Suspicious URL detected",
                    "Extreme sensitive data request"
                ],
                evidence: [
                    "Account lockout creates immediate panic",
                    "Lists specific suspicious activities",
                    "24-hour deadline with permanent closure threat",
                    "Domain societegenerale-banque.fr is suspicious",
                    "Requests EXTREME sensitive information (account, PIN, card number, CVV)",
                    "Threatens 90-day fund freeze"
                ]
            },
            owasp: {
                score: 95,
                patterns: [
                    "Banking credential harvesting",
                    "CVV code collection",
                    "PIN theft",
                    "Complete account takeover kit"
                ],
                evidence: [
                    "Non-Société Générale domain",
                    "Requests CVV code - NEVER legitimate",
                    "Asks for PIN - extreme red flag",
                    "Complete identity theft package"
                ]
            },
            nist: {
                score: 97,
                patterns: [
                    "Complete authentication failure",
                    "Financial institution spoofing"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Société Générale uses societegenerale.fr",
                    "societegenerale-banque.fr is fraudulent"
                ]
            },
            iso27001: {
                score: 96,
                patterns: [
                    "CVV request via email",
                    "PIN request via email",
                    "Complete credential collection"
                ],
                evidence: [
                    "Requests CVV via email - NEVER legitimate",
                    "Asks for PIN - extreme violation",
                    "Banks NEVER request CVV or PIN"
                ]
            },
            nessus: {
                score: 92,
                patterns: [
                    "French banking phishing",
                    "Account lockout scam"
                ],
                evidence: [
                    "Known Société Générale phishing pattern"
                ]
            },
            openvas: {
                score: 94,
                patterns: [
                    "Account closure threat",
                    "Fund freeze threat",
                    "Complete account takeover"
                ],
                evidence: [
                    "Threatens permanent account closure",
                    "90-day fund freeze creates extreme panic",
                    "24-hour deadline",
                    "Requests complete account takeover package"
                ]
            }
        },
        ollama: {
            summary: "Il s'agit d'un email de phishing CRITIQUE usurpant l'identité de la Société Générale. Il utilise de fausses alertes de blocage de compte pour voler les identifiants bancaires complets, y compris les codes PIN et CVV.",
            reasoning: "Indicateurs CRITIQUES de phishing: (1) Échec complet de l'authentification. (2) Usurpation de domaine - societegenerale-banque.fr n'est PAS officiel. (3) Demandes de données EXTRÊMES - code PIN, numéro de carte complet, code CVV par email n'est JAMAIS légitime. (4) Violation de processus - les banques ne demandent JAMAIS les codes PIN ou CVV. (5) Menaces multiples sévères - fermeture définitive, gel des fonds pendant 90 jours. (6) Tous les frameworks ont obtenu des scores de 92%+. (7) La Société Générale gère les alertes de sécurité exclusivement via l'application mobile ou le site web sécurisé. Cet email est conçu pour une prise de contrôle immédiate du compte.",
            recommendations: [
                "Supprimez cet email IMMÉDIATEMENT - c'est une arnaque EXTRÊMEMENT dangereuse",
                "Ne cliquez sur AUCUN lien et ne fournissez AUCUNE information",
                "Ne JAMAIS fournir votre code PIN, CVV ou mot de passe par email",
                "Les banques ne demandent JAMAIS les codes PIN ou CVV",
                "Vérifiez votre compte réel sur societegenerale.fr ou appelez le 09 69 39 39 00",
                "Si vous avez cliqué et saisi des informations, prenez des mesures IMMÉDIATES: (1) Contactez la Société Générale immédiatement, (2) Changez vos mots de passe, (3) Faites opposition sur vos cartes, (4) Surveillez vos transactions",
                "Signalez cette arnaque à la Société Générale et à Pharos",
                "Le phishing bancaire est extrêmement dangereux",
                "Les alertes légitimes arrivent via l'application mobile ou le site web sécurisé"
            ]
        }
    },

    // Email 58 - French MEDIUM TP - Free Internet Provider Scam
    {
        id: 58,
        subject: "Free: Votre abonnement internet sera suspendu",
        from: "service@free-internet.fr",
        language: "fr",
        riskLevel: "MEDIUM",
        classification: "TP",
        body: `Bonjour,

Votre abonnement Free internet sera suspendu en raison d'un problème de paiement.

Numéro d'abonné: FR123456789
Montant impayé: 29,99 €
Date de suspension: 13 février 2026

RÉGULARISER VOTRE PAIEMENT: http://free-paiement.fr/regler

Pour éviter la suspension de votre connexion internet:
• Payez maintenant en ligne
• Régularisez votre situation

Si vous ne payez pas avant le 13 février:
• Votre internet sera coupé
• Des frais de rétablissement (49 €) seront appliqués
• Votre ligne téléphonique sera suspendue

Payez maintenant pour éviter la coupure.

Free SAS
8 Rue de la Ville l'Évêque
75008 Paris, France

Ceci est une notification automatique.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 76,
                patterns: [
                    "Urgency keyword: suspendu",
                    "Urgency keyword: impayé",
                    "Urgency keyword: coupé",
                    "Suspicious URL detected",
                    "Service suspension threat"
                ],
                evidence: [
                    "Internet suspension creates urgency",
                    "Unpaid amount creates concern",
                    "Domain free-internet.fr is suspicious",
                    "Threatens additional fees (€49)",
                    "Phone line suspension threat"
                ]
            },
            owasp: {
                score: 70,
                patterns: [
                    "Payment information harvesting",
                    "ISP billing scam"
                ],
                evidence: [
                    "Non-Free domain with payment path",
                    "URL designed to collect payment information"
                ]
            },
            nist: {
                score: 79,
                patterns: [
                    "Authentication failure",
                    "ISP spoofing"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Free uses free.fr",
                    "free-internet.fr is fraudulent"
                ]
            },
            iso27001: {
                score: 73,
                patterns: [
                    "Payment request via email link"
                ],
                evidence: [
                    "Requests payment via email link",
                    "Free handles billing through official website"
                ]
            },
            nessus: {
                score: 68,
                patterns: [
                    "ISP billing scam",
                    "Service suspension theme"
                ],
                evidence: [
                    "Known French ISP phishing pattern"
                ]
            },
            openvas: {
                score: 72,
                patterns: [
                    "Service loss fear",
                    "Additional fee threat",
                    "Multiple service disruption"
                ],
                evidence: [
                    "Threatens internet and phone suspension",
                    "Additional €49 fee creates urgency",
                    "Deadline creates pressure"
                ]
            }
        },
        ollama: {
            summary: "Il s'agit d'un email de phishing à risque moyen usurpant l'identité de Free. Il utilise de fausses menaces de suspension d'abonnement pour voler les informations de paiement.",
            reasoning: "Plusieurs indicateurs suggèrent du phishing: (1) Échec complet de l'authentification. (2) Usurpation de domaine - free-internet.fr et free-paiement.fr ne sont PAS des domaines officiels de Free (officiel: free.fr). (3) Menaces de suspension d'internet et de téléphone. (4) Frais de rétablissement (€49) créent une urgence supplémentaire. (5) Scores des frameworks dans la fourchette 68-79%. (6) Free envoie les notifications de paiement via l'espace abonné sur free.fr.",
            recommendations: [
                "Supprimez cet email - c'est du phishing",
                "Ne cliquez sur aucun lien",
                "Vérifiez votre compte réel sur free.fr",
                "Free gère les paiements via l'espace abonné",
                "Signalez cette arnaque à Free et à Pharos"
            ]
        }
    },

    // Email 59 - French LOW TN - Doctolib Appointment Reminder
    {
        id: 59,
        subject: "Doctolib: Rappel de votre rendez-vous médical",
        from: "noreply@doctolib.fr",
        language: "fr",
        riskLevel: "LOW",
        classification: "TN",
        body: `Bonjour Max Mustermann,

Rappel de votre rendez-vous médical.

Praticien: Dr. Sophie Martin
Spécialité: Médecin généraliste
Date: 14 février 2026
Heure: 14:30
Adresse: 25 Rue de la République, 75011 Paris

Gérer votre rendez-vous:
www.doctolib.fr/mes-rendez-vous

Annuler ou modifier:
www.doctolib.fr/rendez-vous/123456

Préparez votre consultation:
• Carte Vitale
• Carte de mutuelle
• Ordonnances en cours

Doctolib
53 Avenue d'Iéna
75116 Paris, France

Ceci est un rappel automatique.`,
        authentication: {
            dmarc: "pass",
            spf: "pass",
            dkim: "pass"
        },
        frameworks: {
            mlClassifier: {
                score: 12,
                patterns: [],
                evidence: [
                    "No urgency keywords",
                    "Standard appointment reminder"
                ]
            },
            owasp: {
                score: 8,
                patterns: [],
                evidence: [
                    "All URLs point to official doctolib.fr"
                ]
            },
            nist: {
                score: 7,
                patterns: [],
                evidence: [
                    "Perfect authentication"
                ]
            },
            iso27001: {
                score: 10,
                patterns: [],
                evidence: [
                    "No sensitive data requests"
                ]
            },
            nessus: {
                score: 8,
                patterns: [],
                evidence: [
                    "No malware"
                ]
            },
            openvas: {
                score: 9,
                patterns: [],
                evidence: [
                    "Legitimate appointment reminder"
                ]
            }
        },
        ollama: {
            summary: "Il s'agit d'un rappel de rendez-vous médical légitime de Doctolib. Tous les contrôles d'authentification sont passés parfaitement.",
            reasoning: "Tous les indicateurs confirment la légitimité: (1) Authentification parfaite. (2) Domaine officiel - noreply@doctolib.fr est correct. (3) Tous les liens pointent vers doctolib.fr. (4) Tous les frameworks ont obtenu des scores très faibles (7-12%).",
            recommendations: [
                "Sûr à lire - c'est un rappel légitime de Doctolib",
                "Notez votre rendez-vous (14 février 2026 à 14:30)",
                "Préparez vos documents (Carte Vitale, mutuelle)",
                "Aucune action de sécurité requise"
            ]
        }
    },

    // Email 60 - French HIGH TP - Leboncoin Payment Scam
    {
        id: 60,
        subject: "Leboncoin: Paiement sécurisé pour votre achat",
        from: "paiement@leboncoin-securise.fr",
        language: "fr",
        riskLevel: "HIGH",
        classification: "TP",
        body: `Bonjour,

Un vendeur attend votre paiement pour finaliser votre achat sur Leboncoin.

Article: iPhone 14 Pro Max 256GB
Prix: 850,00 €
Vendeur: Jean Dupont
Référence: LBC2026-8492

EFFECTUER LE PAIEMENT SÉCURISÉ: http://leboncoin-paiement.fr/secure?ref=8492

Leboncoin Paiement Sécurisé garantit:
• Protection de l'acheteur
• Remboursement si problème
• Transaction sécurisée

Pour finaliser votre achat:
1. Cliquez sur le lien de paiement
2. Entrez vos coordonnées bancaires
3. Confirmez le paiement

Le vendeur expédiera l'article dès réception du paiement.

ATTENTION: Ce lien expire dans 24 heures. Si vous ne payez pas, l'article sera proposé à un autre acheteur.

Leboncoin
85 Boulevard Haussmann
75008 Paris, France

Ceci est une notification de paiement sécurisé.`,
        authentication: {
            dmarc: "fail",
            spf: "fail",
            dkim: "fail"
        },
        frameworks: {
            mlClassifier: {
                score: 89,
                patterns: [
                    "Urgency keyword: ATTENTION",
                    "Urgency keyword: 24 heures",
                    "Urgency keyword: expire",
                    "Suspicious URL detected",
                    "Payment request",
                    "Scarcity tactic (autre acheteur)"
                ],
                evidence: [
                    "Payment urgency creates pressure",
                    "24-hour expiration deadline",
                    "Domain leboncoin-securise.fr is suspicious",
                    "Threatens loss of item to another buyer",
                    "High-value item (€850) increases stakes"
                ]
            },
            owasp: {
                score: 86,
                patterns: [
                    "Payment credential harvesting",
                    "Marketplace scam",
                    "Banking information theft"
                ],
                evidence: [
                    "Non-Leboncoin domain with payment path",
                    "URL designed to collect banking credentials",
                    "Fake secure payment system"
                ]
            },
            nist: {
                score: 91,
                patterns: [
                    "Authentication failure",
                    "Marketplace platform spoofing"
                ],
                evidence: [
                    "All authentication checks failed",
                    "Official Leboncoin uses leboncoin.fr",
                    "leboncoin-securise.fr is fraudulent"
                ]
            },
            iso27001: {
                score: 87,
                patterns: [
                    "Banking credentials via email link",
                    "Fake secure payment system"
                ],
                evidence: [
                    "Requests banking credentials via email",
                    "Leboncoin's real secure payment is integrated in the platform"
                ]
            },
            nessus: {
                score: 84,
                patterns: [
                    "Marketplace payment scam",
                    "Leboncoin impersonation"
                ],
                evidence: [
                    "Known French marketplace phishing pattern"
                ]
            },
            openvas: {
                score: 88,
                patterns: [
                    "Item loss fear (scarcity)",
                    "Payment urgency",
                    "Fake buyer protection"
                ],
                evidence: [
                    "Threatens loss of item to another buyer",
                    "24-hour deadline creates urgency",
                    "Fake buyer protection claims",
                    "High-value item (€850) increases motivation"
                ]
            }
        },
        ollama: {
            summary: "Il s'agit d'un email de phishing à haut risque usurpant l'identité de Leboncoin. Il utilise de fausses notifications de paiement sécurisé pour voler les coordonnées bancaires.",
            reasoning: "Indicateurs critiques de phishing: (1) Échec complet de l'authentification. (2) Usurpation de domaine - leboncoin-securise.fr et leboncoin-paiement.fr ne sont PAS des domaines officiels de Leboncoin (officiel: leboncoin.fr). (3) Faux système de paiement sécurisé - Leboncoin a un vrai système intégré à la plateforme. (4) Urgence - expiration dans 24 heures avec menace de perte de l'article. (5) Tactique de rareté - menace qu'un autre acheteur prendra l'article. (6) Tous les frameworks ont obtenu des scores de 84%+. (7) Article de grande valeur (€850) augmente la motivation. (8) Le vrai système de paiement sécurisé de Leboncoin est accessible uniquement via la plateforme, jamais par email.",
            recommendations: [
                "Supprimez cet email immédiatement - c'est une arnaque de phishing",
                "Ne cliquez sur AUCUN lien et ne fournissez AUCUNE information bancaire",
                "Leboncoin ne envoie JAMAIS de liens de paiement par email",
                "Le vrai 'Leboncoin Paiement Sécurisé' est accessible uniquement via la plateforme",
                "Si vous avez un achat en cours, connectez-vous directement sur leboncoin.fr",
                "Si vous avez cliqué et saisi des informations bancaires, contactez votre banque IMMÉDIATEMENT",
                "Surveillez vos transactions bancaires",
                "Signalez cette arnaque à Leboncoin et à Pharos",
                "Les arnaques Leboncoin sont très courantes - toujours vérifier via la plateforme officielle",
                "Ne jamais payer en dehors du système de paiement sécurisé intégré à Leboncoin"
            ]
        }
    }
];

// Export for use in frontend
if (typeof module !== 'undefined' && module.exports) {
    module.exports = emailData;
}
