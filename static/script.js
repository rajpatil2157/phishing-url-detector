document.addEventListener("DOMContentLoaded", function () {
  const canvas = document.getElementById("findingsChart");

  if (!canvas) {
    return;
  }

  const findings = window.phishingFindings || [];

  const highCount = findings.filter(
    (finding) => finding.severity === "HIGH",
  ).length;

  const mediumCount = findings.filter(
    (finding) => finding.severity === "MEDIUM",
  ).length;

  const lowCount = findings.filter(
    (finding) => finding.severity === "LOW",
  ).length;

  new Chart(canvas, {
    type: "doughnut",

    data: {
      labels: ["High Risk", "Medium Risk", "Low Risk"],

      datasets: [
        {
          data: [highCount, mediumCount, lowCount],

          backgroundColor: ["#f85149", "#d29922", "#3fb950"],

          borderColor: "#0d1117",
          borderWidth: 3,
        },
      ],
    },

    options: {
      responsive: true,
      maintainAspectRatio: false,

      plugins: {
        legend: {
          position: "bottom",

          labels: {
            color: "#c9d1d9",
            padding: 20,
          },
        },
      },
    },
  });
});
// Detection Categories Chart

const categoryCanvas = document.getElementById("categoryChart");

if (categoryCanvas && window.phishingFeatures) {
  const features = window.phishingFeatures;

  const categories = {
    "Transport Security": 0,
    "Host Analysis": 0,
    "URL Structure": 0,
    Encoding: 0,
    Parameters: 0,
  };

  // Transport security
  if (!features.https) {
    categories["Transport Security"]++;
  }

  // Host analysis
  if (features.ip_address) {
    categories["Host Analysis"]++;
  }

  if (features.punycode) {
    categories["Host Analysis"]++;
  }

  if (features.url_shortener) {
    categories["Host Analysis"]++;
  }

  if (features.entropy > 3.8) {
    categories["Host Analysis"]++;
  }

  // URL structure
  if (features.url_length > 100) {
    categories["URL Structure"]++;
  }

  if (features.hostname_length > 50) {
    categories["URL Structure"]++;
  }

  if (features.domain_components >= 4) {
    categories["URL Structure"]++;
  }

  if (features.hyphens >= 3) {
    categories["URL Structure"]++;
  }

  if (features.digit_ratio > 0.3) {
    categories["URL Structure"]++;
  }

  // Encoding
  if (features.percent_encoding) {
    categories["Encoding"]++;
  }

  if (features.double_slash) {
    categories["Encoding"]++;
  }

  if (features.decoded_analysis) {
    categories["Encoding"]++;
  }

  // Parameters
  if (features.suspicious_parameters.length > 0) {
    categories["Parameters"]++;
  }

  new Chart(categoryCanvas, {
    type: "bar",

    data: {
      labels: Object.keys(categories),

      datasets: [
        {
          label: "Detected Indicators",
          data: Object.values(categories),
          backgroundColor: "#58a6ff",
          borderRadius: 6,
        },
      ],
    },

    options: {
      responsive: true,
      maintainAspectRatio: false,

      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            stepSize: 1,
            color: "#8b949e",
          },

          grid: {
            color: "#30363d",
          },
        },

        x: {
          ticks: {
            color: "#8b949e",
          },

          grid: {
            display: false,
          },
        },
      },

      plugins: {
        legend: {
          labels: {
            color: "#c9d1d9",
          },
        },
      },
    },
  });
}
