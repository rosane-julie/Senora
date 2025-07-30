from flask import Flask, request, jsonify, send_file, session, render_template
import base64
import io
import logging

from asn1_parser import decode_ber, encode_ber

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = 'super-secret-key-change-me'


@app.route('/')
def index():
    return render_template('edit.html')


@app.route('/upload', methods=['POST'])
def upload():
    xml_file = request.files.get('decoder')
    ber_file = request.files.get('cdr')
    if not xml_file or not ber_file:
        return jsonify({'error': 'Both decoder and CDR files are required'}), 400

    xml_bytes = xml_file.read()
    ber_bytes = ber_file.read()
    try:
        decoded, spec = decode_ber(xml_bytes, ber_bytes)
    except Exception as exc:
        logging.exception('Decode failed')
        return jsonify({'error': f'Failed to decode data: {exc}'}), 400

    session['spec'] = base64.b64encode(spec.encode('utf-8')).decode('utf-8')
    session['original'] = base64.b64encode(ber_bytes).decode('utf-8')
    return jsonify(decoded)


@app.route('/save', methods=['POST'])
def save():
    json_data = request.get_json()
    spec_b64 = session.get('spec')
    if json_data is None or spec_b64 is None:
        return jsonify({'error': 'Missing session data'}), 400

    spec = base64.b64decode(spec_b64).decode('utf-8')
    try:
        encoded = encode_ber(spec, json_data)
    except Exception as exc:
        logging.exception('Encode failed')
        return jsonify({'error': f'Failed to encode data: {exc}'}), 400

    return send_file(
        io.BytesIO(encoded),
        as_attachment=True,
        download_name='modified_cdr.dat',
        mimetype='application/octet-stream'
    )


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
