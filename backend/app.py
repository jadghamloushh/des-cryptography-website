# backend/app.py

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy  # Import SQLAlchemy
from flask_migrate import Migrate  # Import Migrate
from .des import des_encrypt, des_decrypt
from .key_expansion import generate_keys
from .utils import hex_to_bin, bin_to_hex, ascii_to_hex, is_valid_hex, is_valid_binary
import time
import random
from io import BytesIO
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.units import inch
import magic  # For MIME type detection
import logging
import base64  # Import base64 for encoding
from datetime import datetime
import os  # For environment variables
# from openai import OpenAI  # Uncomment if using OpenAI
from reportlab.lib.enums import TA_CENTER
import json  # For JSON serialization
from openai import OpenAI
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configure rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'history.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy and Flask-Migrate
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Constants
ALLOWED_EXTENSIONS = {'txt'}

# Set maximum allowed payload to 1MB (adjust as needed)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1 MB

# Define the History model
class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    operation = db.Column(db.String(20), nullable=False)  # 'encrypt', 'decrypt', 'generate_key'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    key_hex = db.Column(db.String(16), nullable=True)
    key_binary = db.Column(db.String(64), nullable=True)
    key_base64 = db.Column(db.String(24), nullable=True)
    
    # New fields for Input
    input_data = db.Column(db.Text, nullable=True)
    input_format = db.Column(db.String(10), nullable=True)  # 'hex', 'text', 'binary', 'file'
    input_hex = db.Column(db.String(64), nullable=True)
    input_text = db.Column(db.Text, nullable=True)
    
    # New fields for Output
    output_data = db.Column(db.Text, nullable=True)
    output_format = db.Column(db.String(10), nullable=True)  # 'hex', 'text', 'binary', 'file'
    output_hex = db.Column(db.String(64), nullable=True)
    output_text = db.Column(db.Text, nullable=True)
    
    time_taken = db.Column(db.Float, nullable=True)  # in milliseconds
    round_details = db.Column(db.Text, nullable=True)  # JSON serialized

    def to_dict(self):
        return {
            'id': self.id,
            'operation': self.operation,
            'timestamp': self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            'key_hex': self.key_hex,
            'key_binary': self.key_binary,
            'key_base64': self.key_base64,
            'input_data': self.input_data,
            'input_format': self.input_format,
            'input_hex': self.input_hex,
            'input_text': self.input_text,
            'output_data': self.output_data,
            'output_format': self.output_format,
            'output_hex': self.output_hex,
            'output_text': self.output_text,
            'time_taken': self.time_taken,
            'round_details': json.loads(self.round_details) if self.round_details else []
        }

# Initialize the database (only needed once)
# After creating the model, run the following commands in the terminal:
# flask db init
# flask db migrate -m "Initial migration."
# flask db upgrade

def save_history(operation, key_hex=None, key_binary=None, key_base64=None,
                input_data=None, input_format=None, input_hex=None, input_text=None,
                output_data=None, output_format=None, output_hex=None, output_text=None,
                time_taken=None, round_details=None):
    history_entry = History(
        operation=operation,
        key_hex=key_hex,
        key_binary=key_binary,
        key_base64=key_base64,
        input_data=input_data,
        input_format=input_format,
        input_hex=input_hex,
        input_text=input_text,
        output_data=output_data,
        output_format=output_format,
        output_hex=output_hex,
        output_text=output_text,
        time_taken=time_taken,
        round_details=json.dumps(round_details) if round_details else None
    )
    db.session.add(history_entry)
    db.session.commit()

def allowed_file(file_stream, filename):
    """
    Check if the uploaded file has an allowed extension and MIME type.
    """
    if '.' in filename and \
       filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
        # Check MIME type using magic
        try:
            mime = magic.from_buffer(file_stream.read(1024), mime=True)
            file_stream.seek(0)  # Reset stream position
            return mime == 'text/plain'
        except Exception as e:
            logger.error(f"MIME type detection failed: {str(e)}")
            return False
    return False

def convert_input(data, input_format):
    """
    Convert input data based on the specified format to binary.

    Args:
        data (str): The input data as a string.
        input_format (str): The format of the input data ('hex', 'text', 'binary').

    Returns:
        list: A list of bits representing the binary data.

    Raises:
        ValueError: If the input data is invalid or not in the expected format.
    """
    if input_format == 'hex':
        if not is_valid_hex(data):
            raise ValueError("Invalid hexadecimal input.")
        return hex_to_bin(data)
    elif input_format == 'text':
        # Ensure text is ASCII
        try:
            data.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError("Text contains non-ASCII characters.")
        hex_data = ascii_to_hex(data)
        return hex_to_bin(hex_data)
    elif input_format == 'binary':
        if not is_valid_binary(data):
            raise ValueError("Invalid binary input.")
        if len(data) != 64:
            raise ValueError("Binary input must be exactly 64 bits.")
        return [int(bit) for bit in data]
    else:
        raise ValueError("Unsupported input format.")

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'success': False, 'message': 'File is too large. Maximum allowed size is 1MB.'}), 413

@app.route('/encrypt', methods=['POST'])
@limiter.limit("10 per minute")  # Example: 10 requests per minute
def encrypt():
    """
    Encrypt a message using DES.

    Expects multipart/form-data with:
    - 'key': string (hexadecimal, 16 characters)
    - 'input_format': string ('hex', 'text', 'binary', 'file')
    - 'message': string or file, depending on 'input_format'

    Returns:
        JSON response with ciphertext, round details, time taken, and success status.
    """ 

    if 'input_format' not in request.form:     
        return jsonify({'success': False, 'message': 'Input format is required.'}), 400

    input_format = request.form['input_format'].lower()

    # Retrieve and validate key
    key_hex = request.form.get('key', '').strip()
    if not key_hex or len(key_hex) != 16 or not is_valid_hex(key_hex):
        return jsonify({'success': False, 'message': 'Key must be exactly 16 hexadecimal characters.'}), 400

    try:
        key_bin = hex_to_bin(key_hex)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid hexadecimal key.'}), 400

    # Initialize input variables
    input_data = ''
    input_hex = 'N/A'
    input_text = 'N/A'

    # Retrieve message based on input_format
    if input_format == 'file':
        if 'message' not in request.files:
            return jsonify({'success': False, 'message': 'No file part in the request.'}), 400
        file = request.files['message']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No selected file.'}), 400
        if file and allowed_file(file.stream, file.filename):
            # Secure the filename
            filename = secure_filename(file.filename)
            logger.info(f"File uploaded: {filename} from {request.remote_addr}")

            # Process the file (in-memory)
            try:
                content = file.read().decode('utf-8').strip()
            except UnicodeDecodeError:
                return jsonify({'success': False, 'message': 'File contains invalid UTF-8 characters.'}), 400

            # Ensure content is valid ASCII
            try:
                content.encode('ascii')
            except UnicodeEncodeError:
                return jsonify({'success': False, 'message': 'File contains non-ASCII characters.'}), 400

            # Directly convert hex to binary without re-conversion
            try:
                message_bin = hex_to_bin(content)
            except Exception as e:
                return jsonify({'success': False, 'message': f'Failed to convert hex to binary: {str(e)}'}), 400

            input_data = content  # Store hex content as input_data
            input_hex = content
            input_text = 'N/A'
        else:
            return jsonify({'success': False, 'message': 'Invalid file type. Only .txt files are allowed.'}), 400
    else:
        message = request.form.get('message', '').strip()
        if not message:
            return jsonify({'success': False, 'message': 'Message is required.'}), 400
        try:
            message_bin = convert_input(message, input_format)
            input_data = message
            if input_format == 'hex':
                input_hex = message
                input_text = 'N/A'
            elif input_format == 'text':
                input_hex = ascii_to_hex(message)
                input_text = message
            elif input_format == 'binary':
                input_hex = bin_to_hex(message_bin)
                input_text = 'N/A'
            else:
                input_hex = 'N/A'
                input_text = 'N/A'
        except ValueError as ve:
            return jsonify({'success': False, 'message': str(ve)}), 400

    # Ensure message is 64 bits (16 hex characters)
    if len(message_bin) != 64:
        return jsonify({'success': False, 'message': 'Message must be exactly 64 bits (16 hexadecimal characters).' }), 400

    # Perform encryption
    try:
        start_time = time.time()
        ciphertext_bin, round_details = des_encrypt(message_bin, key_bin)
        end_time = time.time()
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        return jsonify({'success': False, 'message': f'Encryption failed: {str(e)}'}), 500

    ciphertext_hex = bin_to_hex(ciphertext_bin)
    elapsed_time = float((end_time - start_time) * 1_000)  # Convert to milliseconds

    # Save history with new fields
    save_history(
        operation='encrypt',
        key_hex=key_hex,
        key_binary=''.join(str(bit) for bit in key_bin),
        key_base64=base64.b64encode(bytes.fromhex(key_hex)).decode('utf-8'),
        input_data=input_data,
        input_format=input_format,
        input_hex=input_hex,
        input_text=input_text,
        output_data=ciphertext_hex,
        output_format='hex',
        output_hex=ciphertext_hex,
        output_text='N/A',  # Encrypted data is hex, so text is not applicable
        time_taken=elapsed_time,
        round_details=round_details
    )

    # Prepare detailed round details for frontend
    detailed_rounds = []
    for round_info in round_details:
        detailed_rounds.append({
            'round': round_info['round'],
            'subkey': round_info['subkey'],
            'left_before': round_info['left_before'],
            'right_before': round_info['right_before'],
            'expanded_right': round_info['expanded_right'],
            'xor_with_subkey': round_info['xor_with_subkey'],
            'sbox_details': round_info['sbox_details'],
            'permutation_output': round_info['permutation_output'],
            'left_after': round_info['left_after'],
            'right_after': round_info['right_after']
        })

    response = {
        'success': True,
        'ciphertext': ciphertext_hex,
        'round_details': detailed_rounds,  # Updated to include detailed information
        'time_taken': elapsed_time
    }
    return jsonify(response), 200


@app.route('/decrypt', methods=['POST'])
@limiter.limit("10 per minute")  # Example: 10 requests per minute
def decrypt():
    """
    Decrypt a ciphertext using DES.

    Expects multipart/form-data with:
    - 'key': string (hexadecimal, 16 characters)
    - 'input_format': string ('hex', 'text', 'binary', 'file')
    - 'ciphertext': string or file, depending on 'input_format'

    Returns:
        JSON response with decrypted text, round details, time taken, and success status.
    """
    if 'input_format' not in request.form:
        return jsonify({'success': False, 'message': 'Input format is required.'}), 400

    input_format = request.form['input_format'].lower()

    # Retrieve and validate key
    key_hex = request.form.get('key', '').strip()
    if not key_hex or len(key_hex) != 16 or not is_valid_hex(key_hex):
        return jsonify({'success': False, 'message': 'Key must be exactly 16 hexadecimal characters.'}), 400

    try:
        key_bin = hex_to_bin(key_hex)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid hexadecimal key.'}), 400

    # Initialize input variables
    input_data = ''
    input_hex = 'N/A'
    input_text = 'N/A'

    # Retrieve ciphertext based on input_format
    if input_format == 'file':
        if 'ciphertext' not in request.files:
            return jsonify({'success': False, 'message': 'No file part in the request.'}), 400
        file = request.files['ciphertext']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No selected file.'}), 400
        if file and allowed_file(file.stream, file.filename):
            # Secure the filename
            filename = secure_filename(file.filename)
            logger.info(f"File uploaded for decryption: {filename} from {request.remote_addr}")

            # Process the file (in-memory)
            try:
                content = file.read().decode('utf-8').strip()
            except UnicodeDecodeError:
                return jsonify({'success': False, 'message': 'File contains invalid UTF-8 characters.'}), 400

            # Ensure content is valid ASCII
            try:
                content.encode('ascii')
            except UnicodeEncodeError:
                return jsonify({'success': False, 'message': 'File contains non-ASCII characters.'}), 400

            # Directly convert hex to binary without re-conversion
            try:
                message_bin = hex_to_bin(content)
            except Exception as e:
                return jsonify({'success': False, 'message': f'Failed to convert hex to binary: {str(e)}'}), 400

            input_data = content  # Store hex content as input_data
            input_hex = content
            input_text = 'N/A'
        else:
            return jsonify({'success': False, 'message': 'Invalid file type. Only .txt files are allowed.'}), 400
    else:
        ciphertext = request.form.get('ciphertext', '').strip()
        if not ciphertext:
            return jsonify({'success': False, 'message': 'Ciphertext is required.'}), 400
        try:
            message_bin = convert_input(ciphertext, input_format)
            input_data = ciphertext  # Store the original ciphertext
            if input_format == 'hex':
                input_hex = ciphertext
                input_text = 'N/A'
            elif input_format == 'text':
                input_hex = ascii_to_hex(ciphertext)
                input_text = ciphertext
            elif input_format == 'binary':
                input_hex = bin_to_hex(message_bin)
                input_text = 'N/A'
            else:
                input_hex = 'N/A'
                input_text = 'N/A'
        except ValueError as ve:
            return jsonify({'success': False, 'message': str(ve)}), 400

    # Ensure ciphertext is 64 bits (16 hex characters)
    if len(message_bin) != 64:
        return jsonify({'success': False, 'message': 'Ciphertext must be exactly 64 bits (16 hexadecimal characters).' }), 400

    # Perform decryption
    try:
        start_time = time.time()
        decrypted_bin, round_details = des_decrypt(message_bin, key_bin)
        end_time = time.time()
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        return jsonify({'success': False, 'message': f'Decryption failed: {str(e)}'}), 500

    decrypted_hex = bin_to_hex(decrypted_bin)
    try:
        decrypted_text = bytes.fromhex(decrypted_hex).decode('utf-8', errors='ignore')
    except ValueError:
        decrypted_text = 'Unable to decode decrypted text.'
    elapsed_time = float((end_time - start_time)*1_000)  # Convert to milliseconds

    # Save history with new fields
    save_history(
        operation='decrypt',
        key_hex=key_hex,
        key_binary=''.join(str(bit) for bit in key_bin),
        key_base64=base64.b64encode(bytes.fromhex(key_hex)).decode('utf-8'),
        input_data=input_data,
        input_format=input_format,
        input_hex=input_hex,
        input_text=input_text,
        output_data=decrypted_text,
        output_format='text',
        output_hex=decrypted_hex,
        output_text=decrypted_text,
        time_taken=elapsed_time,
        round_details=round_details
    )

    # Prepare detailed round details for frontend
    detailed_rounds = []
    for round_info in round_details:
        detailed_rounds.append({
            'round': round_info['round'],
            'subkey': round_info['subkey'],
            'left_before': round_info['left_before'],
            'right_before': round_info['right_before'],
            'expanded_right': round_info['expanded_right'],
            'xor_with_subkey': round_info['xor_with_subkey'],
            'sbox_details': round_info['sbox_details'],
            'permutation_output': round_info['permutation_output'],
            'left_after': round_info['left_after'],
            'right_after': round_info['right_after']
        })

    response = {
        'success': True,
        'decrypted_hex': decrypted_hex,
        'decrypted_text': decrypted_text,
        'round_details': detailed_rounds,  # Updated to include detailed information
        'time_taken': elapsed_time
    }
    return jsonify(response), 200

@app.route('/generate_key', methods=['GET'])
@limiter.limit("100 per day")  # Example: 100 requests per day
def generate_key_route():
    """
    Generate a random 16-character hexadecimal key, its binary, and Base64 representations.

    Returns:
        JSON response with the generated key in hex, binary, and Base64 formats.
    """
    key_hex = ''.join(random.choice('0123456789ABCDEF') for _ in range(16))
    key_bin = ''.join(bin(int(c, 16))[2:].zfill(4) for c in key_hex)  # Convert each hex char to 4-bit binary
    key_bytes = bytes.fromhex(key_hex)
    key_base64 = base64.b64encode(key_bytes).decode('utf-8')

    logger.info(f"Generated key: {key_hex} ({key_bin}) {key_base64} for {request.remote_addr}")

    # Save history
    save_history(
        operation='generate_key',
        key_hex=key_hex,
        key_binary=key_bin,
        key_base64=key_base64,
        time_taken=None,  # No time taken for key generation
        round_details=None  # No round details
    )

    return jsonify({
        'key_hex': key_hex,
        'key_binary': key_bin,
        'key_base64': key_base64
    }), 200

@app.route('/convert_text_to_hex', methods=['POST'])
def convert_text_to_hex_route():
    """
    Convert ASCII text to hexadecimal.

    Expects JSON with:
    - 'text': string

    Returns:
        JSON response with the hexadecimal representation.
    """
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({'success': False, 'message': 'Text is required.'}), 400

    text = data['text']
    try:
        # Ensure text is ASCII
        text.encode('ascii')
        hex_str = ascii_to_hex(text)
    except UnicodeEncodeError:
        return jsonify({'success': False, 'message': 'Text contains non-ASCII characters.'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': f'Conversion failed: {str(e)}'}), 500

    return jsonify({'success': True, 'hex': hex_str}), 200

@app.route('/convert_bin_to_hex', methods=['POST'])
def convert_bin_to_hex_route():
    """
    Convert binary string to hexadecimal.

    Expects JSON with:
    - 'binary': string (64 bits)

    Returns:
        JSON response with the hexadecimal representation.
    """
    data = request.get_json()
    if not data or 'binary' not in data:
        return jsonify({'success': False, 'message': 'Binary string is required.'}), 400

    bin_str = data['binary'].strip()
    if not is_valid_binary(bin_str) or len(bin_str) != 64:
        return jsonify({'success': False, 'message': 'Binary string must be exactly 64 bits.'}), 400

    try:
        hex_str = bin_to_hex([int(bit) for bit in bin_str])
    except Exception as e:
        return jsonify({'success': False, 'message': f'Conversion failed: {str(e)}'}), 500

    return jsonify({'success': True, 'hex': hex_str}), 200

@app.route('/generate_report', methods=['POST'])
@limiter.limit("5 per hour")
def generate_report():
    """
    Generate a PDF report of the encryption/decryption process.

    Expects JSON with:
    - 'reportType': string ('Encryption' or 'Decryption')
    - 'roundDetails': list of round detail objects
    - 'timeTaken': float
    - 'resultHex': string
    - 'keyHex': string (optional)
    - 'keyBinary': string (optional)
    - 'keyBase64': string (optional)

    Returns:
        PDF file as attachment.
    """
    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    required_fields = ['reportType', 'roundDetails', 'timeTaken', 'resultHex']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing field: {field}'}), 400

    # Additional validation: check types
    if not isinstance(data['reportType'], str):
        return jsonify({'message': 'Invalid reportType.'}), 400
    if not isinstance(data['roundDetails'], list):
        return jsonify({'message': 'Invalid roundDetails.'}), 400
    if not isinstance(data['timeTaken'], (int, float)):
        return jsonify({'message': 'Invalid timeTaken.'}), 400
    if not isinstance(data['resultHex'], str):
        return jsonify({'message': 'Invalid resultHex.'}), 400

    # Generate PDF using ReportLab's Platypus
    try:
        buffer = BytesIO()
        # Use landscape orientation with letter size
        doc = SimpleDocTemplate(
            buffer,
            pagesize=landscape(letter),
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        elements = []
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name='CenterHeading',
            alignment=TA_CENTER,
            fontSize=18,
            spaceAfter=20
        ))
        styles.add(ParagraphStyle(
            name='Justify',
            alignment=4,  # Justified
            fontSize=12,
            spaceAfter=12
        ))
        styles.add(ParagraphStyle(
            name='TableHeader',
            alignment=TA_CENTER,
            fontSize=10,
            fontName='Helvetica-Bold',
            textColor=colors.whitesmoke  # Header text color to white
        ))
        styles.add(ParagraphStyle(
            name='TableContent',
            alignment=TA_CENTER,
            fontSize=8,
            fontName='Helvetica',
        ))

        # Title
        elements.append(Paragraph(f"{data['reportType']} Report", styles['CenterHeading']))

        # Time Taken and Result
        elements.append(Paragraph(f"<b>Time Taken:</b> {data['timeTaken']} milliseconds", styles['Justify']))
        elements.append(Paragraph(f"<b>{data['reportType']} Result (Hex):</b> {data['resultHex']}", styles['Justify']))
        elements.append(Spacer(1, 12))

        # Key Information (if provided)
        if all(k in data for k in ('keyHex', 'keyBinary', 'keyBase64')):
            elements.append(Paragraph("Key Information:", styles['Heading2']))
            elements.append(Spacer(1, 12))

            # Define key_data with labels and values
            key_data = [
                [Paragraph('Key Hex', styles['TableHeader']), Paragraph(data['keyHex'], styles['TableContent'])],
                [Paragraph('Key Binary', styles['TableHeader']), Paragraph(data['keyBinary'], styles['TableContent'])],
                [Paragraph('Key Base64', styles['TableHeader']), Paragraph(data['keyBase64'], styles['TableContent'])],
            ]

            # Create Key Information table with two columns
            key_table = Table(key_data, colWidths=[1.5 * inch, 5 * inch])

            # Define table style
            key_table_style = TableStyle([
                # Style for the first column (Labels)
                ('BACKGROUND', (0, 0), (0, -1), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (0, -1), 10),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),

                # Style for the second column (Values)
                ('BACKGROUND', (1, 0), (1, -1), colors.beige),
                ('TEXTCOLOR', (1, 0), (1, -1), colors.black),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (1, 0), (1, -1), 10),
                ('ALIGN', (1, 0), (1, -1), 'LEFT'),

                # Add grid lines
                ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
            ])

            # Apply style
            key_table.setStyle(key_table_style)

            # Add table to elements
            elements.append(key_table)
            elements.append(Spacer(1, 24))

        # Round Details Header
        elements.append(Paragraph("Round Details:", styles['Heading2']))
        elements.append(Spacer(1, 12))

        # Define table data with headers
        table_data = [
            [
                Paragraph('Round', styles['TableHeader']),
                Paragraph('Subkey', styles['TableHeader']),
                Paragraph('L Before', styles['TableHeader']),
                Paragraph('R Before', styles['TableHeader']),
                Paragraph('Exp Right', styles['TableHeader']),
                Paragraph('XOR Sub', styles['TableHeader']),
                Paragraph('S-Box Output', styles['TableHeader']),
                Paragraph('Perm Output', styles['TableHeader']),
                Paragraph('L After', styles['TableHeader']),
                Paragraph('R After', styles['TableHeader'])
            ]
        ]

        # Populate table data with Paragraphs for wrapping
        for round_detail in data['roundDetails']:
            # Validate round_detail structure
            required_round_fields = ['round', 'subkey', 'left_before', 'right_before',
                                     'expanded_right', 'xor_with_subkey',
                                     'sbox_output', 'permutation_output',
                                     'left_after', 'right_after']
            if not all(k in round_detail for k in required_round_fields):
                logger.error(f"Invalid round detail structure: {round_detail}")
                continue  # Skip invalid round details

            table_data.append([
                Paragraph(str(round_detail['round']), styles['TableContent']),
                Paragraph(''.join(str(bit) for bit in round_detail['subkey']), styles['TableContent']),
                Paragraph(''.join(str(bit) for bit in round_detail['left_before']), styles['TableContent']),
                Paragraph(''.join(str(bit) for bit in round_detail['right_before']), styles['TableContent']),
                Paragraph(''.join(str(bit) for bit in round_detail['expanded_right']), styles['TableContent']),
                Paragraph(''.join(str(bit) for bit in round_detail['xor_with_subkey']), styles['TableContent']),
                Paragraph(round_detail['sbox_output'], styles['TableContent']),
                Paragraph(''.join(str(bit) for bit in round_detail['permutation_output']), styles['TableContent']),
                Paragraph(''.join(str(bit) for bit in round_detail['left_after']), styles['TableContent']),
                Paragraph(''.join(str(bit) for bit in round_detail['right_after']), styles['TableContent']),
            ])

        # Define column widths (total = 9.0 inches)
        column_widths = [
            0.5 * inch,  # Round
            1 * inch,    # Subkey
            1 * inch,    # L Before
            1 * inch,    # R Before
            1 * inch,    # Exp Right
            0.9 * inch,  # XOR Sub
            1.2 * inch,  # S-Box Output
            0.8 * inch,  # Perm Output
            0.8 * inch,  # L After
            0.8 * inch   # R After
        ]

        # Create table with defined column widths and split by row
        table = Table(table_data, repeatRows=1, colWidths=column_widths, hAlign='LEFT', splitByRow=1)

        # Define table style
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color to white
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.beige),
            ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
        ])

        # Apply style
        table.setStyle(table_style)

        # Alternate background colors for better readability
        for i in range(1, len(table_data)):
            if i % 2 == 0:
                bg_color = colors.whitesmoke
                table_style.add('BACKGROUND', (0, i), (-1, i), bg_color)

        # Re-apply the updated style
        table.setStyle(table_style)

        # Add table to elements
        elements.append(table)
        elements.append(PageBreak())

        # Optional: Add a summary or additional sections if needed

        # Build PDF
        doc.build(elements)
        buffer.seek(0)

        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"{data['reportType']}_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        return jsonify({'message': f'Failed to generate report: {str(e)}'}), 500

@app.route("/history", methods=["GET"])
@limiter.limit("50 per hour")  # Adjust rate limits as necessary
def get_history():
    """
    Retrieve the history of encryption, decryption, and key generation operations.

    Returns:
        JSON response with a list of history entries.
    """
    try:
        # Fetch all history entries ordered by timestamp descending
        history_entries = History.query.order_by(History.timestamp.desc()).all()
        history_list = [entry.to_dict() for entry in history_entries]
        return jsonify({"success": True, "history": history_list}), 200
    except Exception as e:
        logger.error(f"Failed to retrieve history: {str(e)}")
        return jsonify({"success": False, "message": "Failed to retrieve history."}), 500

# Initialize OpenAI client (ensure API key is set securely)

@app.route('/chat', methods=['POST'])
def chat():
    # Retrieve user input from the frontend
    data = request.get_json()
    user_input = data.get('message', '')

    if not user_input:
        return jsonify({"response": "No input provided."}), 400

    try:
        # Create a chat completion request
        chat_completion = client.chat.completions.create(
            model="gpt-4",  # Ensure the model name is correct
            messages=[
                {"role": "user", "content": user_input}
            ]
        )

        # Extract the chatbot's response correctly
        bot_response = chat_completion.choices[0].message.content  # Proper attribute access
        return jsonify({"response": bot_response})

    except Exception as e:
        return jsonify({"response": f"Error: {str(e)}"}), 500

@app.route("/dashboard", methods=["GET"])
@limiter.limit("50 per hour")  # Adjust rate limits as necessary
def get_dashboard_data():
    """
    API endpoint to provide timing data for the dashboard.
    Retrieves the latest 50 encryption and decryption operations from the history.

    Returns:
        JSON response with timing data and last updated timestamp.
    """
    try:
        # Fetch the latest 50 history entries where time_taken is not null
        history_entries = (
            History.query
            .filter(History.time_taken != None)
            .order_by(History.timestamp.desc())
            .limit(50)
            .all()
        )
        
        # Format the data as a list of dictionaries
        timing_data = [
            {
                'operation': entry.operation.capitalize(),  # Capitalize for better readability
                'time': round(entry.time_taken, 2),        # Round to 2 decimal places
                'timestamp': entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            }
            for entry in history_entries
        ]
        
        # Reverse to show oldest first in the chart
        timing_data.reverse()
        
        logger.info("Dashboard data requested.")
        return jsonify({
            "success": True, 
            "data": timing_data,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 200
    except Exception as e:
        logger.error(f"Failed to retrieve dashboard data: {str(e)}")
        return jsonify({"success": False, "message": "Failed to retrieve dashboard data."}), 500

if __name__ == '__main__':
    app.run(debug=True)



