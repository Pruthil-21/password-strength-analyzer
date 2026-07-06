// ======================================================
// Password Strength Analyzer
// app.js
// ======================================================

document.addEventListener("DOMContentLoaded", () => {

    const passwordInput = document.getElementById("password");
    const toggleButton = document.getElementById("toggle-password");
    const analyzeButton = document.getElementById("analyze-btn");
    const generateButton = document.getElementById("generate-btn");
    const exportButton = document.getElementById("export-btn");
    const historyButton = document.getElementById("history-btn");

    const strengthValue = document.getElementById("strength-value");
    const entropyValue = document.getElementById("entropy-value");
    const crackTimeValue = document.getElementById("cracktime-value");
    const breachValue = document.getElementById("breach-value");

    const requirements = document.getElementById("requirements-list");
    const suggestions = document.getElementById("suggestions");
    const historyContainer = document.getElementById("history-container");

    // ==========================================
    // SHOW / HIDE PASSWORD
    // ==========================================

    toggleButton.addEventListener("click", () => {

        if (passwordInput.type === "password") {

            passwordInput.type = "text";
            toggleButton.innerHTML =
                '<i class="fa-solid fa-eye-slash"></i>';

        } else {

            passwordInput.type = "password";
            toggleButton.innerHTML =
                '<i class="fa-solid fa-eye"></i>';

        }

    });

    // ==========================================
    // ANALYZE PASSWORD
    // ==========================================

    analyzeButton.addEventListener("click", async () => {

        const password = passwordInput.value.trim();

        if (!password) {

            alert("Please enter a password.");
            return;

        }

        try {

            const response = await fetch("/analyze", {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    password: password
                })

            });

            const data = await response.json();

            updateDashboard(data);

        }

        catch (error) {

            console.error(error);

            alert("Analysis failed.");

        }

    });

    // ==========================================
    // GENERATE PASSWORD
    // ==========================================

    generateButton.addEventListener("click", async () => {

        try {

            const response = await fetch("/generate");

            const data = await response.json();

            passwordInput.value = data.password;

        }

        catch {

            alert("Unable to generate password.");

        }

    });

    // ==========================================
    // EXPORT PDF
    // ==========================================

    exportButton.addEventListener("click", () => {

        window.location.href = "/export";

    });

    // ==========================================
    // HISTORY
    // ==========================================

    historyButton.addEventListener("click", async () => {

        try {

            const response = await fetch("/history");

            const history = await response.json();

            historyContainer.innerHTML = "";

            if (history.length === 0) {

                historyContainer.innerHTML =
                    "<p>No previous analysis found.</p>";

                return;

            }

            const table = document.createElement("table");

            table.style.width = "100%";
            table.style.borderCollapse = "collapse";

            table.innerHTML = `

                <tr>

                    <th align="left">Strength</th>

                    <th align="left">Entropy</th>

                    <th align="left">Date</th>

                </tr>

            `;

            history.forEach(item => {

                table.innerHTML += `

                    <tr>

                        <td>${item.strength}</td>

                        <td>${item.entropy} bits</td>

                        <td>${item.date}</td>

                    </tr>

                `;

            });

            historyContainer.appendChild(table);

        }

        catch {

            alert("Unable to load history.");

        }

    });

    // ==========================================
    // UPDATE DASHBOARD
    // ==========================================

    function updateDashboard(data) {

        strengthValue.textContent = data.strength;
        entropyValue.textContent = data.entropy + " bits";
        crackTimeValue.textContent = data.crack_time;
        breachValue.textContent = data.breach;

        requirements.innerHTML = "";

        data.requirements.forEach(item => {

            const li = document.createElement("li");
            li.textContent = item;
            requirements.appendChild(li);

        });

        suggestions.innerHTML = "";

        if (data.reuse) {

            suggestions.innerHTML +=
                "<p style='color:#f59e0b'><strong>⚠ This password has been analyzed before.</strong></p>";

        }

        if (data.suggestions.length === 0) {

            suggestions.innerHTML +=
                "<p style='color:#22c55e'><strong>Password looks strong.</strong></p>";

        }

        else {

            const ul = document.createElement("ul");

            data.suggestions.forEach(item => {

                const li = document.createElement("li");

                li.textContent = item;

                ul.appendChild(li);

            });

            suggestions.appendChild(ul);

        }

    }

});