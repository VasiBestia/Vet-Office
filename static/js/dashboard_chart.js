var pieLabels = JSON.parse(`{{ pie_labels | tojson | default([]) | safe }}`);
var pieValues = JSON.parse(`{{ pie_values | tojson | default([]) | safe }}`);

var ctx = document.getElementById("speciesChart").getContext("2d");

if (ctx) {
    new Chart(ctx, {
        type: 'doughnut',  // sau 'pie' dacă vrei un pie chart simplu
        data: {
            labels: pieLabels,
            datasets: [{
                data: pieValues,
                backgroundColor: ['#0e8f8f', '#ff7043', '#36b9cc', '#f6c23e', '#1cc88a'],
                hoverBackgroundColor: ['#0b7070', '#e65c2e', '#2c9faf', '#dda20a', '#17a673'],
                hoverBorderColor: "rgba(234, 236, 244, 1)",
            }],
        },
        options: {
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    backgroundColor: "rgb(255,255,255)",
                    bodyColor: "#858796",
                    borderColor: '#dddfeb',
                    borderWidth: 1,
                    padding: 10,
                    displayColors: false,
                },
                legend: {
                    display: true,
                    position: 'bottom',
                },
            },
            cutout: '75%',  // în loc de cutoutPercentage
        }
    });
}
