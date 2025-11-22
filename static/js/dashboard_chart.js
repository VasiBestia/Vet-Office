// dashboard_charts.js

// Funcție care desenează graficele, acceptând datele necesare ca argumente
function drawDashboardCharts(alergiiData, pieData) {
    // --- Configurarea Graficului de Alergii (Linie - Stânga) ---
    const ctxLine = document.getElementById('allergiesChart').getContext('2d');
    new Chart(ctxLine, {
        type: 'line',
        data: {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
            datasets: [{
                label: 'Allergies Detected',
                data: alergiiData, // Corect
                borderColor: '#696cff', 
                tension: 0.4, 
                fill: true,
                backgroundColor: 'rgba(105, 108, 255, 0.1)' 
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } }, 
            scales: {
                y: { beginAtZero: true, grid: { display: true, borderDash: [5, 5] } },
                x: { grid: { display: false } }
            }
        }
    });

    // --- Configurarea Graficului Doughnut (Dreapta) ---
    const ctxDoughnut = document.getElementById('sourcesChart').getContext('2d');
    new Chart(ctxDoughnut, {
        type: 'doughnut',
        data: {
            labels: ['Examinations', 'Interventions', 'Animals'],
            // CORECȚIE AICI: Datele trebuie să fie în datasets: []
            datasets: [{ 
                data: pieData, // Corect
                backgroundColor: ['#696cff', '#71dd37', '#03c3ec'], 
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '75%',
            plugins: {
                legend: { display: false }
            }
        }
    });
}