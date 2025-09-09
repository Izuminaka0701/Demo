# payment_system.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64
import json
import datetime
import re

# ==== Load dữ liệu từ note.json ====
with open("note.json", "r", encoding="utf-8") as f:
    note_data = json.load(f)

card_info = note_data["card_info"]
order_info = note_data["order_info"]
test_cards = note_data["test_cards"]
sample_card = note_data["sample_card"]


class PaymentCryptoSystem:
    """Hệ thống mã hóa RSA-OAEP cho thanh toán trực tuyến"""
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        self.generate_keypair()

    def generate_keypair(self):
        key = RSA.generate(self.key_size)
        self.private_key = key
        self.public_key = key.publickey()
        print(f"✅ Đã tạo cặp khóa RSA-{self.key_size}")

    def get_public_key_pem(self) -> str:
        return self.public_key.export_key().decode()

    def get_private_key_pem(self) -> str:
        return self.private_key.export_key().decode()

    def load_public_key_from_pem(self, pem_data: str):
        self.public_key = RSA.import_key(pem_data)


class PaymentClient:
    """Client-side: Mã hóa thông tin thẻ trước khi gửi (Hybrid RSA + AES-GCM)"""
    def __init__(self, server_public_key_pem: str):
        self.server_public_key = RSA.import_key(server_public_key_pem)

    def validate_card_info(self, card_data: dict) -> bool:
        required_fields = ['card_number', 'expiry_month', 'expiry_year', 'cvv', 'cardholder_name']
        for field in required_fields:
            if field not in card_data or not card_data[field]:
                print(f"❌ Thiếu thông tin: {field}")
                return False
        card_number = re.sub(r'\D', '', str(card_data['card_number']))
        if not (13 <= len(card_number) <= 19):
            print("❌ Số thẻ không hợp lệ")
            return False
        cvv = str(card_data['cvv'])
        if not (3 <= len(cvv) <= 4 and cvv.isdigit()):
            print("❌ CVV không hợp lệ")
            return False
        return True

    def encrypt_card_data(self, card_data: dict) -> str:
        """
        Trả về một JSON string (package) chứa:
          - encrypted_key: RSA_OAEP(encrypted AES key) base64
          - nonce: AES-GCM nonce base64
          - ciphertext: AES-GCM ciphertext base64
          - tag: AES-GCM tag base64
        """
        if not self.validate_card_info(card_data):
            raise ValueError("Thông tin thẻ không hợp lệ")

        # Thêm timestamp để chống replay attack
        card_data = card_data.copy()
        card_data['timestamp'] = datetime.datetime.now().isoformat()
        plaintext = json.dumps(card_data, ensure_ascii=False).encode()

        # 1) Sinh AES key (256-bit) và AES-GCM nonce
        aes_key = get_random_bytes(32)          # AES-256
        nonce = get_random_bytes(12)            # recommended for GCM

        # 2) Mã hoá bằng AES-GCM (authenticated)
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

        # 3) Mã hoá AES key bằng RSA-OAEP (SHA-256)
        cipher_rsa = PKCS1_OAEP.new(self.server_public_key, hashAlgo=SHA256)
        encrypted_key = cipher_rsa.encrypt(aes_key)

        # 4) Đóng gói dưới dạng base64 để truyền qua JSON/HTTP
        package = {
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode()
        }

        return json.dumps(package)

    def mask_sensitive_info(self, card_data: dict) -> dict:
        masked = card_data.copy()
        if 'card_number' in masked:
            card_num = str(masked['card_number'])
            masked['card_number'] = f"****-****-****-{card_num[-4:]}"
        if 'cvv' in masked:
            masked['cvv'] = "***"
        return masked

    def create_payment_request(self, card_data: dict, order_info: dict) -> dict:
        encrypted_card = self.encrypt_card_data(card_data)
        return {
            'order_id': order_info.get('order_id'),
            'amount': order_info.get('amount'),
            'currency': order_info.get('currency', 'VND'),
            'encrypted_card_data': encrypted_card,
            'timestamp': datetime.datetime.now().isoformat()
        }


class PaymentServer:
    """Server-side: Giải mã và xử lý thông tin thanh toán (Hybrid RSA + AES-GCM)"""
    def __init__(self, crypto_system: PaymentCryptoSystem):
        self.crypto_system = crypto_system

    def decrypt_card_data(self, encrypted_data: str) -> dict:
        """
        encrypted_data: JSON string (package) created by PaymentClient.encrypt_card_data()
        Trả về dict chứa thông tin thẻ đã giải mã
        """
        try:
            package = json.loads(encrypted_data)
            encrypted_key = base64.b64decode(package["encrypted_key"])
            nonce = base64.b64decode(package["nonce"])
            ciphertext = base64.b64decode(package["ciphertext"])
            tag = base64.b64decode(package["tag"])

            # 1) Giải mã AES key bằng RSA-OAEP (private key)
            cipher_rsa = PKCS1_OAEP.new(self.crypto_system.private_key, hashAlgo=SHA256)
            aes_key = cipher_rsa.decrypt(encrypted_key)

            # 2) Giải mã ciphertext bằng AES-GCM và verify tag
            cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)
            card_info = json.loads(decrypted.decode())

            # 3) Kiểm tra timestamp (chống replay attack)
            timestamp = datetime.datetime.fromisoformat(card_info['timestamp'])
            time_diff = datetime.datetime.now() - timestamp
            if time_diff.total_seconds() > 300:  # 5 phút
                raise ValueError("Request đã hết hạn")

            return card_info

        except Exception as e:
            # Trả lỗi rõ ràng để debug trong demo; production: log tối thiểu
            raise ValueError(f"Lỗi giải mã: {e}")

    def process_payment(self, payment_request: dict) -> dict:
        try:
            card_data = self.decrypt_card_data(payment_request['encrypted_card_data'])
            masked_card = self.mask_sensitive_info(card_data)
            print(f"🔓 Server nhận được thông tin thẻ: {masked_card}")

            # Giả lập xử lý thanh toán
            payment_result = self.simulate_payment_processing(card_data, payment_request)
            return payment_result

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'transaction_id': None
            }

    def mask_sensitive_info(self, card_data: dict) -> dict:
        masked = card_data.copy()
        if 'card_number' in masked:
            card_num = str(masked['card_number'])
            masked['card_number'] = f"****-****-****-{card_num[-4:]}"
        if 'cvv' in masked:
            masked['cvv'] = "***"
        return masked

    def simulate_payment_processing(self, card_data: dict, payment_request: dict) -> dict:
        return {
            'success': True,
            'transaction_id': f"TXN-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
            'amount': payment_request['amount'],
            'currency': payment_request['currency'],
            'status': 'approved',
            'processing_time': datetime.datetime.now().isoformat()
        }


# ==== DEMO FLOW ====

def demo_online_payment_flow():
    print("=== DEMO HỆ THỐNG THANH TOÁN TRỰC TUYẾN (Hybrid RSA + AES-GCM) ===\n")
    server_crypto = PaymentCryptoSystem(key_size=2048)
    payment_server = PaymentServer(server_crypto)
    public_key_pem = server_crypto.get_public_key_pem()
    payment_client = PaymentClient(public_key_pem)

    print(f"Thông tin đơn hàng: {order_info}")
    print(f"Thông tin thẻ (gốc): {payment_client.mask_sensitive_info(card_info)}")

    payment_request = payment_client.create_payment_request(card_info, order_info)
    print(f"\n✅ Dữ liệu encrypted_card_data size: {len(payment_request['encrypted_card_data'])} chars")
    print("📡 Gửi request lên server...")

    payment_result = payment_server.process_payment(payment_request)

    if payment_result['success']:
        print(f"✅ Thanh toán thành công! Transaction ID: {payment_result['transaction_id']}")
    else:
        print(f"❌ Thanh toán thất bại: {payment_result['error']}")


def demo_different_card_types():
    print("\n=== DEMO CÁC LOẠI THẺ KHÁC NHAU (Hybrid) ===\n")
    server_crypto = PaymentCryptoSystem()
    client = PaymentClient(server_crypto.get_public_key_pem())
    server = PaymentServer(server_crypto)
    for card in test_cards:
        print(f"🔒 Mã hóa thẻ {card['name']}:")
        try:
            encrypted = client.encrypt_card_data(card)
            print(f"  ✅ Mã hóa thành công (size: {len(encrypted)} chars)")
            decrypted = server.decrypt_card_data(encrypted)
            masked = server.mask_sensitive_info(decrypted)
            print(f"  ✅ Giải mã thành công: {masked['cardholder_name']} - ****{masked['card_number'][-4:]}")
        except Exception as e:
            print(f"  ❌ Lỗi: {e}")
        print()


if __name__ == "__main__":
    print("🚀 KHỞI ĐỘNG HỆ THỐNG THANH TOÁN (Hybrid RSA + AES-GCM)")
    demo_online_payment_flow()
    demo_different_card_types()
