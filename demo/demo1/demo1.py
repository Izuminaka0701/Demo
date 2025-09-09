from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import json
import hashlib
import time
from datetime import datetime

class EcommerceSecuritySystem:
    """
    Hệ thống bảo mật giao dịch thương mại điện tử sử dụng AES-128
    Mã hóa dữ liệu đơn hàng và thông tin khách hàng
    """
    
    def __init__(self, master_password: str):
        """
        Khởi tạo hệ thống với master password
        Tạo khóa AES-128 (16 bytes) từ password
        """
        self.key = hashlib.sha256(master_password.encode('utf-8')).digest()[:16]
        self.creation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"🔐 Hệ thống bảo mật khởi tạo thành công lúc {self.creation_time}")
        print(f"🔑 Khóa AES-128: {base64.b64encode(self.key).decode()}")
    
    def encrypt_order_data(self, order_data: dict, mode: str = "GCM") -> dict:
        """
        Mã hóa dữ liệu đơn hàng với các chế độ AES khác nhau
        
        Args:
            order_data (dict): Dữ liệu đơn hàng dạng dictionary
            mode (str): Chế độ mã hóa ("ECB", "CBC", "CTR", "GCM")
        
        Returns:
            dict: Dữ liệu đã mã hóa kèm metadata
        """
        json_data = json.dumps(order_data, ensure_ascii=False, separators=(',', ':'))
        timestamp = datetime.now().isoformat()
        
        result = {
            'encrypted_at': timestamp,
            'mode': mode,
            'original_size': len(json_data)
        }
        
        if mode.upper() == "ECB":
            result.update(self._encrypt_ecb(json_data))
        elif mode.upper() == "CBC":
            result.update(self._encrypt_cbc(json_data))
        elif mode.upper() == "CTR":
            result.update(self._encrypt_ctr(json_data))
        elif mode.upper() == "GCM":
            result.update(self._encrypt_gcm(json_data))
        else:
            raise ValueError("Chế độ mã hóa không được hỗ trợ. Sử dụng: ECB, CBC, CTR, GCM")
        
        result['encrypted_size'] = len(result['data'])
        return result
    
    def decrypt_order_data(self, encrypted_package: dict) -> dict:
        """
        Giải mã dữ liệu đơn hàng
        
        Args:
            encrypted_package (dict): Gói dữ liệu đã mã hóa
        
        Returns:
            dict: Dữ liệu đơn hàng gốc
        """
        mode = encrypted_package['mode']
        
        if mode.upper() == "ECB":
            decrypted_json = self._decrypt_ecb(encrypted_package['data'])
        elif mode.upper() == "CBC":
            decrypted_json = self._decrypt_cbc(encrypted_package)
        elif mode.upper() == "CTR":
            decrypted_json = self._decrypt_ctr(encrypted_package)
        elif mode.upper() == "GCM":
            decrypted_json = self._decrypt_gcm(encrypted_package)
        else:
            raise ValueError(f"Chế độ giải mã không được hỗ trợ: {mode}")
        
        return json.loads(decrypted_json)
    
    # Các phương thức mã hóa riêng biệt
    def _encrypt_ecb(self, data: str) -> dict:
        """Mã hóa ECB (không khuyến khích cho production)"""
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded_data = pad(data.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return {'data': base64.b64encode(encrypted).decode()}
    
    def _decrypt_ecb(self, encrypted_data: str) -> str:
        """Giải mã ECB"""
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        return unpad(decrypted_padded, AES.block_size).decode('utf-8')
    
    def _encrypt_cbc(self, data: str) -> dict:
        """Mã hóa CBC"""
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = pad(data.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return {
            'data': base64.b64encode(encrypted).decode(),
            'iv': base64.b64encode(iv).decode()
        }
    
    def _decrypt_cbc(self, encrypted_package: dict) -> str:
        """Giải mã CBC"""
        iv = base64.b64decode(encrypted_package['iv'])
        encrypted_data = base64.b64decode(encrypted_package['data'])
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        return unpad(decrypted_padded, AES.block_size).decode('utf-8')
    
    def _encrypt_ctr(self, data: str) -> dict:
        """Mã hóa CTR"""
        cipher = AES.new(self.key, AES.MODE_CTR)
        encrypted = cipher.encrypt(data.encode('utf-8'))
        return {
            'data': base64.b64encode(encrypted).decode(),
            'nonce': base64.b64encode(cipher.nonce).decode()
        }
    
    def _decrypt_ctr(self, encrypted_package: dict) -> str:
        """Giải mã CTR"""
        nonce = base64.b64decode(encrypted_package['nonce'])
        encrypted_data = base64.b64decode(encrypted_package['data'])
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        return cipher.decrypt(encrypted_data).decode('utf-8')
    
    def _encrypt_gcm(self, data: str) -> dict:
        """Mã hóa GCM (Khuyến khích - có xác thực)"""
        cipher = AES.new(self.key, AES.MODE_GCM)
        encrypted, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        return {
            'data': base64.b64encode(encrypted).decode(),
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'tag': base64.b64encode(tag).decode()
        }
    
    def _decrypt_gcm(self, encrypted_package: dict) -> str:
        """Giải mã GCM"""
        nonce = base64.b64decode(encrypted_package['nonce'])
        encrypted_data = base64.b64decode(encrypted_package['data'])
        tag = base64.b64decode(encrypted_package['tag'])
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(encrypted_data, tag).decode('utf-8')

# === Dữ liệu mẫu đơn hàng thương mại điện tử ===
def create_sample_order() -> dict:
    """Tạo dữ liệu đơn hàng mẫu"""
    return {
        "order_id": "ORD-2024-001234",
        "customer": {
            "customer_id": "CUST-789012",
            "full_name": "Nguyễn Văn An",
            "email": "nguyen.van.an@email.com",
            "phone": "+84-901-234-567",
            "address": {
                "street": "123 Đường Nguyễn Huệ",
                "ward": "Phường Bến Nghé",
                "district": "Quận 1",
                "city": "Thành phố Hồ Chí Minh",
                "postal_code": "700000"
            }
        },
        "items": [
            {
                "product_id": "PROD-001",
                "name": "iPhone 15 Pro Max 256GB",
                "quantity": 1,
                "unit_price": 34990000,
                "total_price": 34990000
            },
            {
                "product_id": "PROD-002", 
                "name": "Ốp lưng iPhone 15 Pro Max",
                "quantity": 1,
                "unit_price": 790000,
                "total_price": 790000
            }
        ],
        "payment": {
            "method": "credit_card",
            "card_last_four": "4567",
            "card_type": "VISA",
            "billing_address": {
                "street": "123 Đường Nguyễn Huệ",
                "ward": "Phường Bến Nghé", 
                "district": "Quận 1",
                "city": "Thành phố Hồ Chí Minh"
            }
        },
        "order_summary": {
            "subtotal": 35780000,
            "shipping_fee": 50000,
            "tax": 3578000,
            "discount": 0,
            "total": 39408000,
            "currency": "VND"
        },
        "shipping": {
            "method": "express",
            "estimated_delivery": "2024-12-25",
            "tracking_number": "VN1234567890123"
        },
        "order_status": "confirmed",
        "created_at": "2024-12-23T10:30:00Z",
        "notes": "Giao hàng trong giờ hành chính"
    }

def load_order_from_file(filename: str) -> dict:
    """Đọc dữ liệu đơn hàng từ file JSON"""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"⚠️ Không tìm thấy file {filename}, sử dụng dữ liệu mẫu")
        return create_sample_order()

def demonstrate_encryption_performance(security_system: EcommerceSecuritySystem, order_data: dict):
    """Demo hiệu suất các chế độ mã hóa"""
    modes = ["ECB", "CBC", "CTR", "GCM"]
    
    print("\n" + "="*60)
    print("📊 SO SÁNH HIỆU SUẤT CÁC CHẾ ĐỘ MÃ HÓA")
    print("="*60)
    
    for mode in modes:
        print(f"\n🔄 Chế độ {mode}:")
        
        # Đo thời gian mã hóa
        start_time = time.time()
        encrypted = security_system.encrypt_order_data(order_data, mode)
        encrypt_time = time.time() - start_time
        
        # Đo thời gian giải mã
        start_time = time.time()
        decrypted = security_system.decrypt_order_data(encrypted)
        decrypt_time = time.time() - start_time
        
        # Kiểm tra tính toàn vẹn
        integrity_check = order_data == decrypted
        
        print(f"   ⏱️  Thời gian mã hóa: {encrypt_time:.6f} giây")
        print(f"   ⏱️  Thời gian giải mã: {decrypt_time:.6f} giây")
        print(f"   📦 Kích thước gốc: {encrypted['original_size']} bytes")
        print(f"   🔐 Kích thước mã hóa: {encrypted['encrypted_size']} bytes")
        print(f"   ✅ Kiểm tra toàn vẹn: {'PASS' if integrity_check else 'FAIL'}")
        
        if mode == "GCM":
            print(f"   🛡️  Xác thực: CÓ (khuyến khích cho production)")
        else:
            print(f"   ⚠️  Xác thực: KHÔNG")

def main_demo():
    """Demo chính của hệ thống bảo mật thương mại điện tử"""
    print("🛒" + "="*59)
    print("   HỆ THỐNG BẢO MẬT GIAO DỊCH THƯƠNG MẠI ĐIỆN TỬ")
    print("                  AES-128 ENCRYPTION")
    print("="*60)
    
    # Khởi tạo hệ thống bảo mật
    master_password = "EcommerceMasterKey2024!@#$"
    security_system = EcommerceSecuritySystem(master_password)
    
    # Tải dữ liệu đơn hàng (từ file hoặc mẫu)
    try:
        order_data = load_order_from_file("note.json")
    except:
        order_data = create_sample_order()
    
    print(f"\n📋 DỮ LIỆU ĐƠN HÀNG GỐC:")
    print(f"   📦 Mã đơn hàng: {order_data['order_id']}")
    print(f"   👤 Khách hàng: {order_data['customer']['full_name']}")
    print(f"   💰 Tổng tiền: {order_data['order_summary']['total']:,} VND")
    print(f"   📊 Kích thước dữ liệu: {len(json.dumps(order_data))} bytes")
    
    # Demo mã hóa/giải mã với chế độ GCM (khuyến khích)
    print(f"\n🔐 DEMO MÃ HÓA/GIẢI MÃ (CHẾ ĐỘ GCM - KHUYẾN KHÍCH)")
    print("-"*60)
    
    # Mã hóa
    encrypted_order = security_system.encrypt_order_data(order_data, "GCM")
    print(f"✅ Mã hóa thành công lúc: {encrypted_order['encrypted_at']}")
    print(f"🔐 Dữ liệu mã hóa (50 ký tự đầu): {encrypted_order['data'][:50]}...")
    print(f"🔑 Nonce: {encrypted_order['nonce']}")
    print(f"🛡️  Tag xác thực: {encrypted_order['tag']}")
    
    # Giải mã
    decrypted_order = security_system.decrypt_order_data(encrypted_order)
    verification_passed = order_data == decrypted_order
    
    print(f"🔓 Giải mã thành công: {'✅ PASS' if verification_passed else '❌ FAIL'}")
    print(f"📋 Đơn hàng sau giải mã: {decrypted_order['order_id']}")
    
    # Demo hiệu suất các chế độ
    demonstrate_encryption_performance(security_system, order_data)
    
    print(f"\n🎯 KẾT LUẬN:")
    print("   • GCM: Khuyến khích cho production (có xác thực)")
    print("   • CBC/CTR: Phù hợp cho trường hợp cần tương thích")  
    print("   • ECB: KHÔNG khuyến khích (không an toàn)")
    print("\n" + "="*60)

if __name__ == "__main__":
    main_demo()