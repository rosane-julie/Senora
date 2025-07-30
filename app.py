from flask import Flask, request, jsonify, session, send_file, render_template
from pyasn1.codec.ber import decoder as ber_decoder, encoder as ber_encoder
from pyasn1.codec.native import decoder as native_decoder, encoder as native_encoder
from pyasn1.type import univ, namedtype
import binascii
import io
import base64
import logging

# Configure basic logging
logging.basicConfig(level=logging.DEBUG)

# Placeholder for future custom ASN.1 schema
CUSTOM_ASN1_SCHEMA = univ.Sequence(
    componentType=namedtype.NamedTypes(
        # Fields will be defined here in the future
    )
)

app = Flask(__name__)
app.secret_key = 'super-secret-key-change-me'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files.get('asnfile')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400
    # Ensure the file is read in binary mode
    data = file.stream.read()
    # Log first 50 bytes for debugging
    logging.debug("Uploaded data first 50 bytes: %s", data[:50])

    session['orig_bytes'] = base64.b64encode(data).decode('utf-8')
    try:
        asn1_obj, _ = ber_decoder.decode(data, asn1Spec=univ.Sequence())
        py_data = native_decoder.decode(asn1_obj)
    except Exception as exc:
        logging.exception("BER decode failed")
        return jsonify({'error': 'Failed to decode ASN.1 data'}), 400

    hex_view = binascii.hexlify(data).decode('utf-8')
    return jsonify({'json': py_data, 'hex': hex_view})

@app.route('/save', methods=['POST'])
def save():
    json_data = request.get_json()
    if json_data is None:
        return jsonify({'error': 'No data provided'}), 400
    if 'orig_bytes' not in session:
        return jsonify({'error': 'No original data'}), 400
    orig_bytes = base64.b64decode(session['orig_bytes'])
    asn1_spec, _ = ber_decoder.decode(orig_bytes)
    asn1_obj = native_encoder.encode(json_data, asn1Spec=asn1_spec)
    encoded = ber_encoder.encode(asn1_obj)
    return send_file(io.BytesIO(encoded), as_attachment=True,
                     download_name='modified_cdr.dat',
                     mimetype='application/octet-stream')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
