// Chart.js Configuration for DefenderSim

document.addEventListener('DOMContentLoaded', function() {
    // Accuracy Chart (Doughnut)
    const accuracyCtx = document.getElementById('accuracyChart').getContext('2d');
    new Chart(accuracyCtx, {
        type: 'doughnut',
        data: {
            labels: ['True Positive (TP)', 'True Negative (TN)', 'False Positive (FP)', 'False Negative (FN)'],
            datasets: [{
                data: [45, 9, 4, 2],
                backgroundColor: ['#10b981', '#3b82f6', '#f59e0b', '#dc2626'],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value} emails (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });

    // Framework Comparison Chart (Bar)
    const frameworkCtx = document.getElementById('frameworkChart').getContext('2d');
    new Chart(frameworkCtx, {
        type: 'bar',
        data: {
            labels: ['ML Classifier', 'OWASP', 'NIST CSF', 'ISO 27001', 'Nessus', 'OpenVAS'],
            datasets: [{
                label: 'Average Detection Score (%)',
                data: [72, 65, 70, 68, 69, 67],
                backgroundColor: [
                    '#3b82f6',
                    '#8b5cf6',
                    '#ec4899',
                    '#f59e0b',
                    '#10b981',
                    '#06b6d4'
                ],
                borderRadius: 8,
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        callback: function(value) {
                            return value + '%';
                        },
                        font: {
                            size: 11
                        }
                    },
                    grid: {
                        color: '#e2e8f0'
                    }
                },
                x: {
                    ticks: {
                        font: {
                            size: 11
                        }
                    },
                    grid: {
                        display: false
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Detection Score: ${context.parsed.y}%`;
                        }
                    }
                }
            }
        }
    });
});
