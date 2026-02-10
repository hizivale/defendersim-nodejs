// Main JavaScript for DefenderSim Frontend

let currentFilter = 'all';

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    renderEmails(emailData);
    setupFilters();
    setupModal();
});

// Render email cards
function renderEmails(emails) {
    const grid = document.getElementById('emailGrid');
    grid.innerHTML = '';
    
    const filtered = filterEmails(emails, currentFilter);
    
    if (filtered.length === 0) {
        grid.innerHTML = '<p style="text-align: center; grid-column: 1/-1; padding: 40px; color: #64748b;">No emails match the selected filter.</p>';
        return;
    }
    
    filtered.forEach(email => {
        const card = createEmailCard(email);
        grid.appendChild(card);
    });
}

// Create email card element
function createEmailCard(email) {
    const card = document.createElement('div');
    card.className = `email-card ${email.riskLevel}`;
    card.onclick = () => showEmailDetails(email);
    
    card.innerHTML = `
        <div class="risk-badge ${email.riskLevel}">${email.riskLevel} RISK</div>
        <div class="email-lang">${email.language.toUpperCase()}</div>
        <div class="email-subject">${escapeHtml(email.subject)}</div>
        <div class="email-from">From: ${escapeHtml(email.from)}</div>
        <div class="email-classification" style="margin-top: 10px; font-size: 0.85rem; color: #64748b;">
            Classification: <strong>${email.classification}</strong>
        </div>
    `;
    
    return card;
}

// Filter emails
function filterEmails(emails, filter) {
    if (filter === 'all') return emails;
    
    return emails.filter(email => {
        if (filter === 'HIGH' || filter === 'MEDIUM' || filter === 'LOW') {
            return email.riskLevel === filter;
        }
        return email.language === filter;
    });
}

// Setup filter buttons
function setupFilters() {
    const buttons = document.querySelectorAll('.filter-btn');
    buttons.forEach(btn => {
        btn.addEventListener('click', function() {
            buttons.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            currentFilter = this.dataset.filter;
            renderEmails(emailData);
        });
    });
}

// Show email details in modal
function showEmailDetails(email) {
    const modal = document.getElementById('emailModal');
    const modalBody = document.getElementById('modalBody');
    
    const avgScore = calculateAverageScore(email.frameworks);
    
    modalBody.innerHTML = `
        <h2>${escapeHtml(email.subject)}</h2>
        <div style="margin: 20px 0;">
            <span class="risk-badge ${email.riskLevel}">${email.riskLevel} RISK</span>
            <span class="email-lang">${email.language.toUpperCase()}</span>
            <span style="margin-left: 10px; padding: 4px 12px; background: #f1f5f9; border-radius: 12px; font-size: 0.85rem;">
                ${email.classification}
            </span>
        </div>
        
        <div style="background: #f8fafc; padding: 15px; border-radius: 8px; margin: 20px 0;">
            <strong>From:</strong> ${escapeHtml(email.from)}<br>
            <strong>Average Framework Score:</strong> ${avgScore}%
        </div>
        
        <div style="margin: 20px 0;">
            <h3>Email Body</h3>
            <div style="background: white; border: 1px solid #e2e8f0; padding: 15px; border-radius: 8px; white-space: pre-wrap; font-family: monospace; font-size: 0.9rem;">
${escapeHtml(email.body)}
            </div>
        </div>
        
        <div style="margin: 20px 0;">
            <h3>Authentication Results</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px;">
                <div style="padding: 10px; background: ${email.authentication.dmarc === 'pass' ? '#d1fae5' : (email.authentication.dmarc === 'fail' ? '#fee2e2' : '#fef3c7')}; border-radius: 8px; text-align: center;">
                    <strong>DMARC:</strong> ${email.authentication.dmarc.toUpperCase()}
                </div>
                <div style="padding: 10px; background: ${email.authentication.spf === 'pass' ? '#d1fae5' : (email.authentication.spf === 'fail' ? '#fee2e2' : '#fef3c7')}; border-radius: 8px; text-align: center;">
                    <strong>SPF:</strong> ${email.authentication.spf.toUpperCase()}
                </div>
                <div style="padding: 10px; background: ${email.authentication.dkim === 'pass' ? '#d1fae5' : (email.authentication.dkim === 'fail' ? '#fee2e2' : '#fef3c7')}; border-radius: 8px; text-align: center;">
                    <strong>DKIM:</strong> ${email.authentication.dkim.toUpperCase()}
                </div>
            </div>
        </div>
        
        <div style="margin: 20px 0;">
            <h3>Framework Analysis</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
                ${Object.entries(email.frameworks).map(([name, data]) => `
                    <div style="border: 1px solid #e2e8f0; padding: 15px; border-radius: 8px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                            <strong>${formatFrameworkName(name)}</strong>
                            <span style="font-size: 1.2rem; color: ${getScoreColor(data.score)}; font-weight: bold;">${data.score}%</span>
                        </div>
                        ${data.patterns && data.patterns.length > 0 ? `
                            <div style="margin-top: 8px; padding-top: 8px; border-top: 1px solid #e2e8f0;">
                                <small style="color: #64748b; display: block; margin-bottom: 4px;"><strong>Patterns:</strong></small>
                                <small style="color: #64748b;">${data.patterns.join(', ')}</small>
                            </div>
                        ` : ''}
                        ${data.evidence && data.evidence.length > 0 ? `
                            <div style="margin-top: 8px;">
                                <small style="color: #64748b; display: block; margin-bottom: 4px;"><strong>Evidence:</strong></small>
                                <small style="color: #64748b;">${data.evidence.join(', ')}</small>
                            </div>
                        ` : ''}
                    </div>
                `).join('')}
            </div>
        </div>
        
        <div style="margin: 20px 0; background: #eff6ff; padding: 20px; border-radius: 8px; border-left: 4px solid #3b82f6;">
            <h3 style="margin-bottom: 10px; color: #1e40af;">Ollama LLM Analysis (Llama 3.2:3b)</h3>
            <p style="margin-bottom: 10px;"><strong>Summary:</strong> ${escapeHtml(email.ollama.summary)}</p>
            <p style="margin-bottom: 10px;"><strong>Reasoning:</strong> ${escapeHtml(email.ollama.reasoning)}</p>
            <div style="margin-top: 15px;">
                <strong>Recommendations:</strong>
                <ul style="margin-top: 5px; padding-left: 20px;">
                    ${email.ollama.recommendations.map(rec => `<li style="margin: 5px 0;">${escapeHtml(rec)}</li>`).join('')}
                </ul>
            </div>
        </div>
    `;
    
    modal.style.display = 'block';
}

// Calculate average framework score
function calculateAverageScore(frameworks) {
    const scores = Object.values(frameworks).map(f => f.score);
    const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
    return avg.toFixed(1);
}

// Get color based on score
function getScoreColor(score) {
    if (score >= 80) return '#dc2626'; // High risk - red
    if (score >= 50) return '#f59e0b'; // Medium risk - orange
    return '#10b981'; // Low risk - green
}

// Format framework names
function formatFrameworkName(name) {
    const names = {
        mlClassifier: 'ML Classifier',
        owasp: 'OWASP',
        nist: 'NIST CSF',
        iso27001: 'ISO/IEC 27001',
        nessus: 'Nessus',
        openvas: 'OpenVAS'
    };
    return names[name] || name;
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Setup modal
function setupModal() {
    const modal = document.getElementById('emailModal');
    const closeBtn = document.querySelector('.close');
    
    closeBtn.onclick = function() {
        modal.style.display = 'none';
    };
    
    window.onclick = function(event) {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    };
    
    // Close on Escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && modal.style.display === 'block') {
            modal.style.display = 'none';
        }
    });
}
