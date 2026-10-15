\# Phishing URL Detector



A machine-learning-based web application that analyzes URLs to identify potential phishing threats using URL features, rule-based checks, and a trained classification model.



\*\*Developer:\*\* Raj Devendra Chavan  

\*\*Project Type:\*\* Cybersecurity · Machine Learning · Web Application



\## Overview



Phishing attacks use deceptive URLs to trick users into visiting fraudulent websites. This project combines rule-based URL analysis with machine learning to assess potentially malicious URLs and present findings through a web dashboard.



The application is built with Python and Flask and can be deployed as a web service.



\## Features



\- \*\*URL analysis:\*\* Examines submitted URLs for potentially suspicious characteristics.

\- \*\*Rule-based detection:\*\* Uses URL indicators and heuristic checks to identify possible threats.

\- \*\*Machine learning:\*\* Uses a trained text-classification model to estimate whether a URL resembles phishing or legitimate examples.

\- \*\*Combined assessment:\*\* Presents rule-based findings and model predictions to support further investigation.

\- \*\*Risk assessment:\*\* Displays a risk level and analysis results through a web interface.

\- \*\*Input validation:\*\* Validates URL format and applies a maximum input length.

\- \*\*Web deployment:\*\* Designed to run as a Flask application served by Waitress.



\## Technology Stack



| Component | Technology |

|---|---|

| Programming language | Python |

| Web framework | Flask |

| Machine learning | scikit-learn |

| Text feature extraction | TF-IDF |

| Classification model | Logistic Regression |

| Model persistence | joblib |

| Production WSGI server | Waitress |

| Frontend | HTML, CSS, JavaScript |

| Version control | Git and GitHub |

| Deployment | Render |



\## How It Works



1\. The user submits a URL through the web interface.

2\. The application validates the input.

3\. The rule-based detector examines URL characteristics and produces findings.

4\. The machine-learning model estimates the likelihood that the URL belongs to the phishing class.

5\. The application combines the analysis results and displays an assessment to the user.



See \[ARCHITECTURE.md](ARCHITECTURE.md) for the component-level design.



\## Machine Learning Evaluation



The model was evaluated using a held-out test set created through registered-domain grouping to reduce overlap between training and test domains.



| Metric | Result |

|---|---:|

| Test URLs | 43,046 |

| Accuracy | 99.7189% |

| Phishing precision | 100.00% |

| Phishing recall | 99.25% |

| Phishing URLs missed in this test | 121 |

| Legitimate URLs incorrectly flagged in this test | 0 |



These results describe one evaluation dataset and split. They do not guarantee equivalent performance on new, real-world URLs. Dataset composition, distribution shifts, and previously unseen phishing techniques can affect performance.



The application uses a phishing probability threshold of 0.25. This is a model decision threshold, not a guarantee that a URL is safe or malicious.



\## Project Structure



```text

phishing-url-detector/

├── ML/

│   └── models/

│       └── phishing\_validation\_model.joblib

├── static/

│   ├── script.js

│   └── style.css

├── templates/

│   └── index.html

├── app.py

├── detector.py

├── run\_server.py

├── requirements.txt

├── .gitignore

├── README.md

└── ARCHITECTURE.md

```



\## Run Locally



\### 1. Clone the repository



```bash

git clone https://github.com/rajpatil2157/phishing-url-detector.git

cd phishing-url-detector

```



\### 2. Create and activate a virtual environment



Windows PowerShell:



```powershell

python -m venv venv

.\\venv\\Scripts\\Activate.ps1

```



\### 3. Install dependencies



```bash

python -m pip install -r requirements.txt

```



\### 4. Start the application



```bash

python run\_server.py

```



Open `http://127.0.0.1:8080` in your browser.



The trained model file must be present at `ML/models/phishing\_validation\_model.joblib`.



\## Security and Limitations



\- A URL assessment is an indicator, not a definitive security verdict.

\- A legitimate-looking URL may still lead to harmful content.

\- Do not enter confidential information on a website solely because this detector classifies its URL as low risk.

\- Test suspicious URLs using safe, isolated analysis methods rather than opening them directly.

\- Model performance may differ on URLs outside the training distribution.



\## Future Improvements



\- Automated regression and edge-case tests.

\- More extensive evaluation on external datasets.

\- Improved explainability for individual model predictions.

\- Structured detection reports and analysis history.

\- Security hardening and monitoring for the deployed service.



\## Author



\*\*Raj Devendra Chavan\*\*



Computer Science and Engineering student interested in cybersecurity, machine learning, and security tooling.



\- GitHub: \[@rajpatil2157](https://github.com/rajpatil2157)

\- Project repository: \[Phishing URL Detector](https://github.com/rajpatil2157/phishing-url-detector)



\---



\*Developed as an educational cybersecurity and machine-learning project.\*

