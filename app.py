from flask import Flask, request, jsonify
from cryptography.fernet import Fernet

app = Flask(__name__)

key = Fernet.generate_key()
cipher = Fernet(key)


@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        # Get the data from the request
        data = request.json
        if 'message' not in data:
            return jsonify({'error': 'No message provided'}), 400

        message = data['message']

        # Encrypt the message
        encrypted_message = cipher.encrypt(message.encode())

        return jsonify({'encrypted_message': encrypted_message.decode()}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        # Get the data from the request
        data = request.json
        if 'encrypted_message' not in data:
            return jsonify({'error': 'No encrypted message provided'}), 400

        encrypted_message = data['encrypted_message'].encode()

        # Decrypt the message
        decrypted_message = cipher.decrypt(encrypted_message).decode()

        return jsonify({'decrypted_message': decrypted_message}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)