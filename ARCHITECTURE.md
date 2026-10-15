\# Phishing URL Detector — Architecture



\## 1. System Overview



The Phishing URL Detector is a Python web application that combines rule-based URL analysis with machine-learning classification.



The system is organized into four main components:



1\. Frontend interface

2\. Flask application layer

3\. Rule-based detection engine

4\. Machine-learning inference component



\## 2. Architecture Diagram



```mermaid

flowchart TD

&#x20;   A\[User] --> B\[HTML CSS JavaScript Interface]

&#x20;   B --> C\[Flask Application: app.py]

&#x20;   C --> D\[Input Validation]

&#x20;   D --> E\[Rule-Based Analysis: detector.py]

&#x20;   D --> F\[ML Inference]

&#x20;   F --> G\[TF-IDF Vectorizer and Logistic Regression]

&#x20;   G --> H\[Phishing Probability]

&#x20;   E --> I\[Rule Findings and Risk Assessment]

&#x20;   H --> J\[Combined Assessment]

&#x20;   I --> J

&#x20;   J --> K\[Flask Template Rendering]

&#x20;   K --> B

```



\## 3. Component Responsibilities



\### Frontend



\*\*Files:\*\* `templates/index.html`, `static/style.css`, `static/script.js`



Responsibilities:



\- Accept a URL from the user.

\- Submit the URL to the Flask application.

\- Display analysis results and risk indicators.

\- Provide the visual presentation of the detector.



\### Flask Application



\*\*File:\*\* `app.py`



Responsibilities:



\- Handle HTTP requests and form submissions.

\- Validate URL input.

\- Load the trained model at application startup.

\- Coordinate rule-based and machine-learning analysis.

\- Combine the analysis results and render the response.



The application is served by Waitress through `run\_server.py`.



\### Rule-Based Detection



\*\*File:\*\* `detector.py`



Responsibilities:



\- Parse URL components.

\- Inspect URL structure and potentially suspicious indicators.

\- Generate findings and a rule-based risk assessment.

\- Return structured analysis data for the application.



The rule-based result provides a separate source of evidence from the machine-learning prediction.



\### Machine-Learning Inference



\*\*Model file:\*\* `ML/models/phishing\_validation\_model.joblib`



The application loads a previously trained text-classification pipeline using joblib.



The model uses TF-IDF character-level features with Logistic Regression to classify URL strings.



The application compares the model's phishing probability against a configured threshold of `0.25`.



The resulting prediction is an estimate based on learned patterns. It is not a calibrated guarantee of the URL's safety or maliciousness.



\### Web Server and Deployment



\*\*File:\*\* `run\_server.py`



Waitress serves the Flask application. The server reads the deployment port from the `PORT` environment variable, with a local default of `8080`.



The application source code and required model are stored in GitHub. Render builds the service from the repository and runs the server.



\## 4. Request Lifecycle



1\. A user submits a URL.

2\. Flask receives the request.

3\. Input validation checks the URL and its length.

4\. The rule-based engine analyzes URL characteristics.

5\. The machine-learning pipeline estimates the phishing probability.

6\. The application combines the results according to its implemented decision logic.

7\. Flask renders the findings and assessment in the web interface.



\## 5. Model Evaluation



The model was evaluated using a held-out split grouped by registered domain, reducing the risk of the same registered domain appearing in both training and test sets.



Reported test-set accuracy was 99.7189% across 43,046 URLs. Phishing recall was 99.25%, with 121 phishing URLs missed in that test set.



These figures are specific to the dataset and evaluation procedure. They do not establish real-world detection performance for every domain, URL type, or future phishing campaign.



\## 6. Security Considerations



\- Treat submitted URLs as untrusted input.

\- Validate input before processing.

\- Avoid automatically opening submitted URLs.

\- Do not interpret a low-risk result as proof of safety.

\- Keep secrets and credentials out of source control.

\- Monitor deployment logs for errors and unexpected behavior.

\- Re-evaluate the model when the dataset, model, or threshold changes.



\## 7. Current Scope



The current system performs URL-based analysis. It should not be described as a full website scanner, browser protection system, or live threat-intelligence service unless those capabilities are implemented separately.



\## 8. Potential Extensions



\- Automated unit and integration tests.

\- Explainable per-feature detection results.

\- External threat-intelligence integrations.

\- Safe analysis history and report export.

\- Model drift monitoring and periodic evaluation.

