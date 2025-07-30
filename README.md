# Senora ASN Editor

Senora provides a web interface for decoding and editing BER encoded CDR files using XML decoder definitions.

## Installation

Use Python 3 and install the dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Usage

Run the Flask application:

```bash
python app.py
```

Open your browser to `http://localhost:5000`.
Upload an XML decoder and a BER CDR file to view and edit the decoded
content. After editing you can download the modified CDR as a BER file.
