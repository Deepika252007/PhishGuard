# PhishGuard — Phishing URL Risk Analyzer

PhishGuard is a beginner-friendly Python cybersecurity project that reviews URL text for common suspicious patterns and provides an explainable heuristic risk score. It does **not** visit, fetch, or execute the submitted URL.

## Features

- Adds `https://` when a URL has no scheme.
- Flags an `@` symbol in the URL authority.
- Flags IP-address hosts.
- Flags unusually long URLs, many subdomain labels, security-sensitive terms, known URL shorteners, and plain HTTP.
- Shows a score from 0–100, a Low/Medium/High label, and the reasons that contributed to the score.
- Includes unit tests and a Jupyter Notebook.

## Technologies

- Python 3
- Streamlit for the user interface
- `urllib.parse`, `ipaddress`, `re`, and `unittest` from the Python standard library
- `python-docx` to create the report

## Project files

- `app.py` — Streamlit interface
- `scanner.py` — URL normalization and heuristic scoring
- `tests.py` — automated tests
- `Deepika_PhishGuard.ipynb` — explanatory notebook and runnable examples
- `Deepika_ProjectReport.docx` — project report
- `requirements.txt` — Python dependencies

## Setup on Windows

Open Command Prompt or a terminal in the project folder.

```bat
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

If `py` is not available, try `python` instead.

## Run the app

```bat
python -m streamlit run app.py
```

Open the local address printed in the terminal, usually `http://localhost:8501`.

## Run tests

```bat
python -m unittest tests -v
```

## Example inputs

Use these reserved example domains for demonstrations:

- `https://example.com`
- `https://example.org/account/verify`
- `http://192.0.2.1/login` (the IP address is reserved for documentation examples)

These examples are not assertions that any real website is malicious.

## Dataset reference for future evaluation

The [UCI Phishing Websites dataset](https://archive.ics.uci.edu/dataset/327/phishing) is listed as a reference for future evaluation or a future machine-learning extension. **This version is rule-based and does not train a model or use that dataset as training data.** No model accuracy is claimed.

## Risk-score interpretation

The score is a heuristic indicator based on configured text patterns, not a probability. Low risk does not prove a URL is safe, and High risk does not prove it is malicious. The rules can produce false positives and false negatives.

## Ethical and safety notes

- The submitted URL is analyzed as text only; the application does not open it.
- Use the tool for learning, defensive awareness, and authorized testing.
- Do not enter private or sensitive URLs into tools you do not control.
