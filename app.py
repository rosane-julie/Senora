from flask import Flask, request, jsonify, session, send_file, render_template
from pyasn1.codec.ber import decoder as ber_decoder, encoder as ber_encoder
from pyasn1.codec.native import decoder as native_decoder, encoder as native_encoder
import binascii
import io
import base64

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
    data = file.read()
    session['orig_bytes'] = base64.b64encode(data).decode('utf-8')
    asn1_obj, _ = ber_decoder.decode(data)
    py_data = native_decoder.decode(asn1_obj)
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
