/* ==========================================================
   SCAMSHIELD FRONTEND
========================================================== */


/*
    IMPORTANT:

    This is the URL of your ScamShield FastAPI server.

    If your API server runs using:

        uvicorn api_server:app --port 8001

    keep this as:

        http://127.0.0.1:8001
*/

const API_URL = "http://127.0.0.1:8001";


/* ==========================================================
   ELEMENTS
========================================================== */

const messageInput =
    document.getElementById("messageInput");

const analyzeBtn =
    document.getElementById("analyzeBtn");

const buttonText =
    document.getElementById("buttonText");

const loadingSpinner =
    document.getElementById("loadingSpinner");

const resultArea =
    document.getElementById("resultArea");


/* ==========================================================
   SAMPLE MESSAGES
========================================================== */

const phishingMessage =
    "URGENT: Your bank account is locked! " +
    "Unlock now at http://bit.ly/secure-auth-check";


const giftMessage =
    "You won a $500 Amazon gift card! " +
    "Claim instantly here: http://claim-reward.xyz";


const safeMessage =
    "Your verification code is 884102. " +
    "Valid for 5 minutes. Do not share.";


/* ==========================================================
   SAMPLE BUTTONS
========================================================== */

document
    .getElementById("phishingBtn")
    .addEventListener("click", function () {

        messageInput.value =
            phishingMessage;

        messageInput.focus();
    });


document
    .getElementById("giftBtn")
    .addEventListener("click", function () {

        messageInput.value =
            giftMessage;

        messageInput.focus();
    });


document
    .getElementById("safeBtn")
    .addEventListener("click", function () {

        messageInput.value =
            safeMessage;

        messageInput.focus();
    });


/* ==========================================================
   ESCAPE HTML
========================================================== */

function escapeHTML(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


/* ==========================================================
   LOADING STATE
========================================================== */

function setLoading(isLoading) {

    analyzeBtn.disabled =
        isLoading;


    if (isLoading) {

        buttonText.textContent =
            "Analyzing...";

        loadingSpinner.classList.remove(
            "hidden"
        );

    } else {

        buttonText.textContent =
            "Analyze Threat Signals";

        loadingSpinner.classList.add(
            "hidden"
        );
    }
}


/* ==========================================================
   SHOW ERROR
========================================================== */

function showError(message) {

    resultArea.classList.remove(
        "hidden"
    );

    resultArea.innerHTML = `

        <div class="error-message">

            ⚠️ ${escapeHTML(message)}

        </div>

    `;
}


/* ==========================================================
   ANALYZE MESSAGE
========================================================== */

async function analyzeMessage() {

    const message =
        messageInput.value.trim();


    /* ------------------------------------------------------
       VALIDATION
    ------------------------------------------------------ */

    if (!message) {

        showError(
            "Please enter a message or select a sample payload."
        );

        return;
    }


    /* ------------------------------------------------------
       LOADING
    ------------------------------------------------------ */

    setLoading(true);


    resultArea.classList.add(
        "hidden"
    );


    try {

        /* ==================================================
           SEND MESSAGE TO PYTHON BACKEND
        =================================================== */

        const response =
            await fetch(
                `${API_URL}/api/analyze`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        message: message
                    })
                }
            );


        /* --------------------------------------------------
           HTTP ERROR
        -------------------------------------------------- */

        if (!response.ok) {

            throw new Error(
                `Backend returned HTTP ${response.status}`
            );
        }


        /* --------------------------------------------------
           JSON RESPONSE
        -------------------------------------------------- */

        const result =
            await response.json();


        console.log(
            "ScamShield API Result:",
            result
        );


        /* --------------------------------------------------
           DISPLAY RESULT
        -------------------------------------------------- */

        displayResult(result);


    } catch (error) {

        console.error(
            "ScamShield Error:",
            error
        );


        showError(
            "Unable to connect to the ScamShield backend. " +
            "Make sure the FastAPI server is running on port 8001."
        );

    } finally {

        setLoading(false);
    }
}


/* ==========================================================
   ANALYZE BUTTON
========================================================== */

analyzeBtn.addEventListener(
    "click",
    analyzeMessage
);


/* ==========================================================
   ENTER KEY SUPPORT
========================================================== */

messageInput.addEventListener(
    "keydown",
    function (event) {

        /*
            Ctrl + Enter
            or
            Cmd + Enter
        */

        if (
            event.key === "Enter" &&
            (event.ctrlKey || event.metaKey)
        ) {

            event.preventDefault();

            analyzeMessage();
        }
    }
);


/* ==========================================================
   DISPLAY RESULT
========================================================== */

function displayResult(result) {


    /* ------------------------------------------------------
       READ DATA
    ------------------------------------------------------ */

    const riskScore =
        Number(result.risk_score || 0);


    const riskLevel =
        result.risk_level ||
        "LOW RISK";


    const scamType =
        result.scam_type ||
        "No specific scam type detected";


    const indicators =
        Array.isArray(result.indicators)
            ? result.indicators
            : [];


    const recommendation =
        result.recommendation ||
        "Verify the message through an official source.";


    const spamProbability =
        Number(
            result.spam_probability || 0
        ) * 100;


    const safeProbability =
        Number(
            result.safe_probability || 0
        ) * 100;


    const mlPrediction =
        result.ml_prediction ||
        "UNKNOWN";


    /* ------------------------------------------------------
       DETERMINE RISK STATE
    ------------------------------------------------------ */

    let cardClass =
        "result-safe";

    let badgeClass =
        "badge-safe";

    let meterClass =
        "risk-fill-safe";

    let badgeText =
        "LOW RISK";

    let icon =
        "✅";

    let summary =
        "No strong scam indicators were detected by the current analysis.";


    if (
        riskLevel === "HIGH RISK"
    ) {

        cardClass =
            "result-high";

        badgeClass =
            "badge-high";

        meterClass =
            "risk-fill-high";

        badgeText =
            "HIGH RISK DETECTED";

        icon =
            "🚨";

        summary =
            "Multiple scam indicators were detected. Treat this message as potentially dangerous.";

    } else if (
        riskLevel === "SUSPICIOUS"
    ) {

        cardClass =
            "result-warning";

        badgeClass =
            "badge-warning";

        meterClass =
            "risk-fill-warning";

        badgeText =
            "SUSPICIOUS";

        icon =
            "⚠️";

        summary =
            "The message contains suspicious patterns that require additional verification.";
    }


    /* ------------------------------------------------------
       INDICATORS
    ------------------------------------------------------ */

    let indicatorsHTML = "";


    if (indicators.length > 0) {

        indicatorsHTML =
            indicators
                .map(
                    function (indicator) {

                        return `

                            <div class="signal-item">

                                <span>
                                    ${icon}
                                </span>

                                <span>
                                    ${escapeHTML(indicator)}
                                </span>

                            </div>

                        `;
                    }
                )
                .join("");

    } else {

        indicatorsHTML = `

            <div class="signal-item">

                <span>✅</span>

                <span>
                    No strong scam indicators detected.
                </span>

            </div>

        `;
    }


    /* ------------------------------------------------------
       RESULT CARD
    ------------------------------------------------------ */

    resultArea.innerHTML = `

        <div class="result-card ${cardClass}">


            <!-- RESULT HEADER -->

            <div class="result-header">

                <span class="result-title">
                    Assessment Summary
                </span>

                <span class="result-badge ${badgeClass}">
                    ${badgeText}
                </span>

            </div>


            <!-- SUMMARY -->

            <p class="result-summary">

                ${escapeHTML(summary)}

            </p>


            <!-- RISK SCORE -->

            <div class="risk-section">

                <div class="risk-top">

                    <span>
                        Risk Score
                    </span>

                    <span class="risk-value">

                        ${riskScore.toFixed(2)}/100

                    </span>

                </div>


                <div class="risk-meter">

                    <div
                        class="risk-fill ${meterClass}"
                        style="width:${Math.min(
                            riskScore,
                            100
                        )}%"
                    >
                    </div>

                </div>

            </div>


            <!-- META -->

            <div class="meta-grid">


                <div>

                    <div class="meta-label">
                        Scam Type
                    </div>

                    <div class="meta-value">

                        ${escapeHTML(
                            scamType
                        )}

                    </div>

                </div>


                <div>

                    <div class="meta-label">
                        ML Prediction
                    </div>

                    <div class="meta-value">

                        ${escapeHTML(
                            mlPrediction
                        )}

                    </div>

                </div>


            </div>


            <!-- INDICATORS -->

            <div class="indicators">

                <div class="meta-label">

                    Detected Indicators
                    (${indicators.length})

                </div>

                ${indicatorsHTML}

            </div>


            <!-- ML ANALYSIS -->

            <div class="ml-analysis">

                <div class="meta-label">
                    AI Model Analysis
                </div>


                <div class="ml-box">

                    <span>
                        🤖
                    </span>

                    <span>

                        Spam probability:
                        <strong>
                            ${spamProbability.toFixed(2)}%
                        </strong>

                        &nbsp; | &nbsp;

                        Safe probability:
                        <strong>
                            ${safeProbability.toFixed(2)}%
                        </strong>

                    </span>

                </div>

            </div>


            <!-- RECOMMENDATION -->

            <div class="recommendation">

                <div class="meta-label">

                    Safety Recommendation

                </div>


                <div class="recommendation-box">

                    🛡️

                    ${escapeHTML(
                        recommendation
                    )}

                </div>

            </div>


        </div>

    `;


    resultArea.classList.remove(
        "hidden"
    );


    /* ------------------------------------------------------
       SCROLL RESULT INTO VIEW
    ------------------------------------------------------ */

    setTimeout(
        function () {

            resultArea.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

        },
        100
    );
}