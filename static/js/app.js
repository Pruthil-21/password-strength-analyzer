// ======================================================
// Password Strength Analyzer
// app.js
// ======================================================

document.addEventListener("DOMContentLoaded", () => {

    const passwordInput = document.getElementById("password");
    const toggleButton = document.getElementById("toggle-password");
    const analyzeButton = document.getElementById("analyze-btn");
    const generateButton = document.getElementById("generate-btn");
    const copyButton = document.getElementById("copy-btn");
    const exportButton = document.getElementById("export-btn");
    const historyButton = document.getElementById("history-btn");

    const scoreBarFill = document.getElementById("score-bar-fill");
    const scoreNumber = document.getElementById("score-value");
    const strengthValue = document.getElementById("strength-value");
    const entropyValue = document.getElementById("entropy-value");
    const crackTimeValue = document.getElementById("cracktime-value");
    const breachValue = document.getElementById("breach-value");

    const requirements = document.getElementById("requirements-list");
    const weaknessesList = document.getElementById("weaknesses-list");
    const suggestions = document.getElementById("suggestions");
    const historyContainer = document.getElementById("history-container");
    const errorBanner = document.getElementById("error-banner");

    // Generator controls (all optional — app.js still works if a page
    // doesn't include them, e.g. a future stripped-down view)
    const genLength = document.getElementById("gen-length");
    const genUpper = document.getElementById("gen-upper");
    const genLower = document.getElementById("gen-lower");
    const genNumbers = document.getElementById("gen-numbers");
    const genSymbols = document.getElementById("gen-symbols");

    // ==========================================
    // ERROR DISPLAY
    // ==========================================

    function showError(message) {

        if (errorBanner) {

            errorBanner.textContent = message;
            errorBanner.classList.remove("hidden");

        } else {

            alert(message);

        }

    }

    function clearError() {

        if (errorBanner) {

            errorBanner.textContent = "";
            errorBanner.classList.add("hidden");

        }

    }

    // ==========================================
    // SHOW / HIDE PASSWORD
    // ==========================================

    if (toggleButton) {

        toggleButton.addEventListener("click", () => {

            if (passwordInput.type === "password") {

                passwordInput.type = "text";
                toggleButton.innerHTML = '<i class="fa-solid fa-eye-slash"></i>';

            } else {

                passwordInput.type = "password";
                toggleButton.innerHTML = '<i class="fa-solid fa-eye"></i>';

            }

        });

    }

    // ==========================================
    // ANALYZE PASSWORD
    // ==========================================

    if (analyzeButton) {

        analyzeButton.addEventListener("click", async () => {

            const password = passwordInput.value.trim();

            if (!password) {

                showError("Please enter a password.");
                return;

            }

            clearError();

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

                if (!response.ok) {

                    showError(data.error || "Analysis failed.");
                    return;

                }

                updateDashboard(data);

                if (exportButton) {
                    exportButton.disabled = false;
                }

            }

            catch (error) {

                console.error(error);
                showError("Analysis failed. Check your connection and try again.");

            }

        });

    }

    // ==========================================
    // GENERATE PASSWORD
    // ==========================================

    if (generateButton) {

        generateButton.addEventListener("click", async () => {

            const options = {
                length: genLength ? parseInt(genLength.value, 10) : 16,
                uppercase: genUpper ? genUpper.checked : true,
                lowercase: genLower ? genLower.checked : true,
                numbers: genNumbers ? genNumbers.checked : true,
                symbols: genSymbols ? genSymbols.checked : true,
            };

            try {

                const response = await fetch("/generate", {

                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify(options)

                });

                const data = await response.json();

                if (!response.ok) {

                    showError(data.error || "Unable to generate password.");
                    return;

                }

                passwordInput.value = data.password;
                passwordInput.type = "text";

                if (toggleButton) {
                    toggleButton.innerHTML = '<i class="fa-solid fa-eye-slash"></i>';
                }

            }

            catch (error) {

                console.error(error);
                showError("Unable to generate password.");

            }

        });

    }

    // ==========================================
    // COPY GENERATED PASSWORD
    // ==========================================

    if (copyButton) {

        copyButton.addEventListener("click", async () => {

            if (!passwordInput.value) {
                return;
            }

            try {

                await navigator.clipboard.writeText(passwordInput.value);

                const originalIcon = copyButton.innerHTML;
                copyButton.innerHTML = '<i class="fa-solid fa-check"></i>';

                setTimeout(() => {
                    copyButton.innerHTML = originalIcon;
                }, 1200);

            }

            catch (error) {

                console.error(error);
                showError("Unable to copy to clipboard.");

            }

        });

    }

    // ==========================================
    // EXPORT PDF
    // ==========================================

    if (exportButton) {

        exportButton.addEventListener("click", () => {

            window.location.href = "/export";

        });

    }

    // ==========================================
    // HISTORY
    // ==========================================

    if (historyButton) {

        historyButton.addEventListener("click", async () => {

            try {

                const response = await fetch("/history");
                const history = await response.json();

                if (!response.ok) {

                    showError(history.error || "Unable to load history.");
                    return;

                }

                renderHistoryTable(history, historyContainer);

            }

            catch (error) {

                console.error(error);
                showError("Unable to load history.");

            }

        });

    }

    // ==========================================
    // RENDER HISTORY TABLE (shared helper — used here and on the
    // dedicated history page)
    // ==========================================

    function renderHistoryTable(history, container) {

        container.innerHTML = "";

        if (history.length === 0) {

            const emptyMessage = document.createElement("p");
            emptyMessage.textContent = "No previous analysis found.";
            container.appendChild(emptyMessage);
            return;

        }

        const table = document.createElement("table");
        table.className = "history-table";

        const headerRow = document.createElement("tr");

        ["Strength", "Score", "Entropy", "Breached", "Date"].forEach(label => {

            const th = document.createElement("th");
            th.textContent = label;
            headerRow.appendChild(th);

        });

        table.appendChild(headerRow);

        history.forEach(item => {

            const row = document.createElement("tr");

            const cells = [
                item.strength,
                `${item.score}/100`,
                `${item.entropy} bits`,
                item.is_breached ? "Yes" : "No",
                item.date,
            ];

            cells.forEach(value => {

                const td = document.createElement("td");
                td.textContent = value;
                row.appendChild(td);

            });

            table.appendChild(row);

        });

        container.appendChild(table);

    }

    // ==========================================
    // UPDATE DASHBOARD
    // ==========================================

    function updateDashboard(data) {

        if (scoreBarFill) {
            scoreBarFill.style.width = data.score + "%";
        }

        if (scoreNumber) {
            scoreNumber.textContent = data.score;
        }

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

        if (weaknessesList) {

            weaknessesList.innerHTML = "";

            if (data.weaknesses.length === 0) {

                const li = document.createElement("li");
                li.textContent = "No structural weaknesses detected.";
                weaknessesList.appendChild(li);

            } else {

                data.weaknesses.forEach(item => {

                    const li = document.createElement("li");
                    li.textContent = item;
                    weaknessesList.appendChild(li);

                });

            }

        }

        suggestions.innerHTML = "";

        if (data.reuse) {

            const reuseNotice = document.createElement("p");
            reuseNotice.style.color = "#f59e0b";

            const strong = document.createElement("strong");
            strong.textContent = "⚠ This password has been analyzed before.";

            reuseNotice.appendChild(strong);
            suggestions.appendChild(reuseNotice);

        }

        if (data.suggestions.length === 0) {

            const strongMessage = document.createElement("p");
            strongMessage.style.color = "#22c55e";

            const strong = document.createElement("strong");
            strong.textContent = "Password looks strong.";

            strongMessage.appendChild(strong);
            suggestions.appendChild(strongMessage);

        } else {

            const ul = document.createElement("ul");

            data.suggestions.forEach(item => {

                const li = document.createElement("li");
                li.textContent = item;
                ul.appendChild(li);

            });

            suggestions.appendChild(ul);

        }

    }

    // ==========================================
    // DEDICATED HISTORY PAGE
    // (only runs when history.html's elements are present)
    // ==========================================

    const historyTableBody = document.getElementById("history-table-body");
    const historySearch = document.getElementById("history-search");
    const historyRefreshBtn = document.getElementById("history-refresh-btn");
    const historyClearBtn = document.getElementById("history-clear-btn");

    async function loadHistoryPage() {

        const search = historySearch ? historySearch.value.trim() : "";
        const url = search ? `/history?search=${encodeURIComponent(search)}` : "/history";

        try {

            const response = await fetch(url);
            const history = await response.json();

            if (!response.ok) {

                showError(history.error || "Unable to load history.");
                return;

            }

            renderHistoryTableBody(history);

        }

        catch (error) {

            console.error(error);
            showError("Unable to load history.");

        }

    }

    function renderHistoryTableBody(history) {

        historyTableBody.innerHTML = "";

        if (history.length === 0) {

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 7;
            cell.textContent = "No history entries found.";

            row.appendChild(cell);
            historyTableBody.appendChild(row);

            return;

        }

        history.forEach(item => {

            const row = document.createElement("tr");

            const values = [
                item.password_hash.slice(0, 16) + "...",
                item.strength,
                `${item.score}/100`,
                `${item.entropy} bits`,
                item.is_breached ? "Yes" : "No",
                item.date,
            ];

            values.forEach(value => {

                const td = document.createElement("td");
                td.textContent = value;
                row.appendChild(td);

            });

            const actionCell = document.createElement("td");
            const deleteBtn = document.createElement("button");

            deleteBtn.className = "delete-row-btn";
            deleteBtn.innerHTML = '<i class="fa-solid fa-trash"></i>';
            deleteBtn.setAttribute("aria-label", "Delete this entry");

            deleteBtn.addEventListener("click", async () => {

                try {

                    const response = await fetch(`/history/${item.id}`, {
                        method: "DELETE"
                    });

                    const data = await response.json();

                    if (!response.ok) {

                        showError(data.error || "Unable to delete entry.");
                        return;

                    }

                    loadHistoryPage();

                }

                catch (error) {

                    console.error(error);
                    showError("Unable to delete entry.");

                }

            });

            actionCell.appendChild(deleteBtn);
            row.appendChild(actionCell);

            historyTableBody.appendChild(row);

        });

    }

    if (historyTableBody) {

        loadHistoryPage();

        if (historyRefreshBtn) {
            historyRefreshBtn.addEventListener("click", loadHistoryPage);
        }

        if (historySearch) {
            historySearch.addEventListener("keyup", (event) => {
                if (event.key === "Enter") {
                    loadHistoryPage();
                }
            });
        }

        if (historyClearBtn) {

            historyClearBtn.addEventListener("click", async () => {

                if (!confirm("Delete all history? This cannot be undone.")) {
                    return;
                }

                try {

                    const response = await fetch("/history", {
                        method: "DELETE"
                    });

                    const data = await response.json();

                    if (!response.ok) {

                        showError(data.error || "Unable to clear history.");
                        return;

                    }

                    loadHistoryPage();

                }

                catch (error) {

                    console.error(error);
                    showError("Unable to clear history.");

                }

            });

        }

    }

});