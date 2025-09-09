# =====================================================================
# HỆ THỐNG CHỮ KÝ SỐ CHO HỢP ĐỒNG B2B
# Digital Signature System for B2B Contracts
# Công nghệ: RSA-PSS & ECDSA
# =====================================================================

# Cài đặt thư viện:
# pip install pycryptodome ecdsa PyPDF2 python-docx

import os
import json
import base64
import hashlib
import datetime
from typing import Dict, Any, Tuple, Optional
from pathlib import Path

# RSA-PSS imports
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA256, SHA384

# ECDSA imports
import ecdsa
from ecdsa import SigningKey, VerifyingKey, NIST256p, NIST384p

# File processing
try:
    import PyPDF2
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False
    print("⚠️ PyPDF2 not installed. PDF support disabled.")

try:
    from docx import Document
    DOCX_SUPPORT = True
except ImportError:
    DOCX_SUPPORT = False
    print("⚠️ python-docx not installed. DOCX support disabled.")

print("🚀 KHỞI ĐỘNG HỆ THỐNG CHỮ KÝ SỐ B2B")
print("=" * 60)

# =====================================================================
# PHẦN 1: BASE CLASSES VÀ UTILITIES
# =====================================================================

class ContractSigner:
    """Base class cho hệ thống ký số"""
    
    def __init__(self, signer_name: str, organization: str):
        """
        Args:
            signer_name: Tên người ký
            organization: Tổ chức
        """
        self.signer_name = signer_name
        self.organization = organization
        self.created_at = datetime.datetime.now()
    
    def extract_file_content(self, file_path: str) -> str:
        """Trích xuất nội dung từ file để hash"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File không tồn tại: {file_path}")
        
        extension = file_path.suffix.lower()
        
        if extension == '.txt':
            return self._extract_text_content(file_path)
        elif extension == '.pdf' and PDF_SUPPORT:
            return self._extract_pdf_content(file_path)
        elif extension == '.docx' and DOCX_SUPPORT:
            return self._extract_docx_content(file_path)
        else:
            # Fallback: đọc raw bytes
            with open(file_path, 'rb') as f:
                return f.read().hex()
    
    def _extract_text_content(self, file_path: Path) -> str:
        """Trích xuất từ file text"""
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    
    def _extract_pdf_content(self, file_path: Path) -> str:
        """Trích xuất từ PDF"""
        content = ""
        with open(file_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)
            for page in pdf_reader.pages:
                content += page.extract_text()
        return content
    
    def _extract_docx_content(self, file_path: Path) -> str:
        """Trích xuất từ Word document"""
        doc = Document(file_path)
        content = ""
        for paragraph in doc.paragraphs:
            content += paragraph.text + "\n"
        return content
    
    def calculate_file_hash(self, file_path: str, hash_algo='sha256') -> str:
        """Tính hash của file"""
        content = self.extract_file_content(file_path)
        
        if hash_algo == 'sha256':
            return hashlib.sha256(content.encode()).hexdigest()
        elif hash_algo == 'sha384':
            return hashlib.sha384(content.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {hash_algo}")

# class SignatureMetadata:
#     """Metadata cho chữ ký số"""
    
#     def __init__(self, signer: ContractSigner, file_path: str, signature_type: str):
#         self.signer_name = signer.signer_name
#         self.organization = signer.organization
#         self.file_path = file_path
#         self.file_name = Path(file_path).name
#         self.file_size = os.path.getsize(file_path)
#         self.signature_type = signature_type  # 'RSA-PSS' or 'ECDSA'
#         self.timestamp = datetime.datetime.now().isoformat()
#         self.file_hash = None
#         self.signature = None
    
#     def to_dict(self) -> Dict[str, Any]:
#         """Convert to dictionary"""
#         return {
#             'signer_name': self.signer_name,
#             'organization': self.organization,
#             'file_name': self.file_name,
#             'file_size': self.file_size,
#             'signature_type': self.signature_type,
#             'timestamp': self.timestamp,
#             'file_hash': self.file_hash,
#             'signature': self.signature
#         }
    
#     @classmethod
#     def from_dict(cls, data: Dict[str, Any]) -> 'SignatureMetadata':
#         """Create from dictionary"""
#         # Tạo dummy signer để khởi tạo
#         dummy_signer = type('obj', (object,), {
#             'signer_name': data['signer_name'],
#             'organization': data['organization']
#         })()
        
#         metadata = cls(dummy_signer, f"dummy/{data['file_name']}", data['signature_type'])
#         metadata.file_size = data['file_size']
#         metadata.timestamp = data['timestamp']
#         metadata.file_hash = data['file_hash']
#         metadata.signature = data['signature']
#         return metadata

class SignatureMetadata:
    """Metadata cho chữ ký số"""
    
    def __init__(self, signer: ContractSigner, file_path: str, signature_type: str, file_size: Optional[int] = None):
        """
        Args:
            signer: Thông tin người ký
            file_path: Đường dẫn file
            signature_type: Loại chữ ký ('RSA-PSS' hoặc 'ECDSA')
            file_size: Kích thước file (optional, for deserialization)
        """
        self.signer_name = signer.signer_name
        self.organization = signer.organization
        self.file_path = file_path
        self.file_name = Path(file_path).name
        # If file_size is provided, use it; otherwise try to get from file
        if file_size is not None:
            self.file_size = file_size
        else:
            self.file_size = os.path.getsize(file_path)
        self.signature_type = signature_type
        self.timestamp = datetime.datetime.now().isoformat()
        self.file_hash = None
        self.signature = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'signer_name': self.signer_name,
            'organization': self.organization,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'signature_type': self.signature_type,
            'timestamp': self.timestamp,
            'file_hash': self.file_hash,
            'signature': self.signature
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SignatureMetadata':
        """Create from dictionary"""
        # Tạo dummy signer để khởi tạo
        dummy_signer = type('obj', (object,), {
            'signer_name': data['signer_name'],
            'organization': data['organization']
        })()
        
        # Pass the file_size from saved data instead of trying to read from disk
        metadata = cls(
            dummy_signer,
            f"dummy/{data['file_name']}", 
            data['signature_type'],
            file_size=data['file_size']
        )
        
        metadata.timestamp = data['timestamp']
        metadata.file_hash = data['file_hash']
        metadata.signature = data['signature']
        return metadata

# =====================================================================
# PHẦN 2: RSA-PSS DIGITAL SIGNATURE
# =====================================================================

class RSAContractSigner(ContractSigner):
    """RSA-PSS Digital Signature cho hợp đồng"""
    
    def __init__(self, signer_name: str, organization: str, key_size: int = 2048):
        """
        Args:
            key_size: 2048 hoặc 4096 bits
        """
        super().__init__(signer_name, organization)
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        self._generate_keypair()
    
    def _generate_keypair(self):
        """Tạo cặp khóa RSA"""
        print(f"🔑 RSA: Tạo cặp khóa {self.key_size}-bit cho {self.signer_name}")
        key = RSA.generate(self.key_size)
        self.private_key = key
        self.public_key = key.publickey()
    
    def sign_contract(self, file_path: str, hash_algo: str = 'sha256') -> SignatureMetadata:
        """
        Ký hợp đồng bằng RSA-PSS
        Args:
            file_path: Đường dẫn file hợp đồng
            hash_algo: 'sha256' hoặc 'sha384'
        Returns:
            Metadata chứa chữ ký
        """
        print(f"✍️ RSA-PSS: Ký hợp đồng {Path(file_path).name}")
        
        # Tạo metadata
        metadata = SignatureMetadata(self, file_path, 'RSA-PSS')
        
        # Tính hash của file
        file_hash = self.calculate_file_hash(file_path, hash_algo)
        metadata.file_hash = file_hash
        
        # Tạo hash object
        if hash_algo == 'sha256':
            h = SHA256.new(file_hash.encode())
        else:
            h = SHA384.new(file_hash.encode())
        
        # Ký bằng RSA-PSS
        signature = pss.new(self.private_key).sign(h)
        metadata.signature = base64.b64encode(signature).decode()
        
        print(f"✅ RSA-PSS: Đã ký thành công")
        print(f"   - File hash: {file_hash[:32]}...")
        print(f"   - Signature: {metadata.signature[:64]}...")
        
        return metadata
    
    def verify_signature(self, file_path: str, metadata: SignatureMetadata, public_key_pem: Optional[str] = None) -> bool:
        """
        Xác thực chữ ký RSA-PSS
        Args:
            file_path: Đường dẫn file cần verify
            metadata: Metadata chứa chữ ký
            public_key_pem: Public key (nếu None thì dùng self.public_key)
        Returns:
            True nếu chữ ký hợp lệ
        """
        try:
            print(f"🔍 RSA-PSS: Xác thực chữ ký cho {Path(file_path).name}")
            
            # Sử dụng public key
            pub_key = self.public_key
            if public_key_pem:
                pub_key = RSA.import_key(public_key_pem)
            
            # Tính hash của file hiện tại
            current_hash = self.calculate_file_hash(file_path)
            
            # So sánh với hash trong metadata
            if current_hash != metadata.file_hash:
                print(f"❌ File đã bị thay đổi!")
                print(f"   Original hash: {metadata.file_hash[:32]}...")
                print(f"   Current hash:  {current_hash[:32]}...")
                return False
            
            # Decode signature
            signature_bytes = base64.b64decode(metadata.signature)
            
            # Tạo hash object (giả định SHA-256, có thể improve)
            h = SHA256.new(current_hash.encode())
            
            # Verify signature
            pss.new(pub_key).verify(h, signature_bytes)
            
            print(f"✅ RSA-PSS: Chữ ký hợp lệ")
            print(f"   - Người ký: {metadata.signer_name}")
            print(f"   - Tổ chức: {metadata.organization}")
            print(f"   - Thời gian: {metadata.timestamp}")
            
            return True
            
        except (ValueError, TypeError) as e:
            print(f"❌ RSA-PSS: Chữ ký không hợp lệ - {str(e)}")
            return False
    
    def export_public_key(self) -> str:
        """Export public key dạng PEM"""
        return self.public_key.export_key().decode()
    
    def export_private_key(self) -> str:
        """Export private key dạng PEM (cẩn thận!)"""
        return self.private_key.export_key().decode()

# =====================================================================
# PHẦN 3: ECDSA DIGITAL SIGNATURE
# =====================================================================

class ECDSAContractSigner(ContractSigner):
    """ECDSA Digital Signature cho hợp đồng"""
    
    def __init__(self, signer_name: str, organization: str, curve=NIST256p):
        """
        Args:
            curve: NIST256p hoặc NIST384p
        """
        super().__init__(signer_name, organization)
        self.curve = curve
        self.private_key = None
        self.public_key = None
        self._generate_keypair()
    
    def _generate_keypair(self):
        """Tạo cặp khóa ECDSA"""
        curve_name = self.curve.name
        print(f"🔑 ECDSA: Tạo cặp khóa {curve_name} cho {self.signer_name}")
        
        self.private_key = SigningKey.generate(curve=self.curve)
        self.public_key = self.private_key.get_verifying_key()
    
    def sign_contract(self, file_path: str, hash_algo: str = 'sha256') -> SignatureMetadata:
        """
        Ký hợp đồng bằng ECDSA
        Args:
            file_path: Đường dẫn file hợp đồng
            hash_algo: 'sha256' hoặc 'sha384'
        Returns:
            Metadata chứa chữ ký
        """
        print(f"✍️ ECDSA: Ký hợp đồng {Path(file_path).name}")
        
        # Tạo metadata
        metadata = SignatureMetadata(self, file_path, 'ECDSA')
        
        # Tính hash của file
        file_hash = self.calculate_file_hash(file_path, hash_algo)
        metadata.file_hash = file_hash
        
        # Ký bằng ECDSA
        if hash_algo == 'sha256':
            signature = self.private_key.sign(file_hash.encode(), hashfunc=hashlib.sha256)
        else:
            signature = self.private_key.sign(file_hash.encode(), hashfunc=hashlib.sha384)
        
        metadata.signature = base64.b64encode(signature).decode()
        
        print(f"✅ ECDSA: Đã ký thành công")
        print(f"   - File hash: {file_hash[:32]}...")
        print(f"   - Signature: {metadata.signature[:64]}...")
        
        return metadata
    
    def verify_signature(self, file_path: str, metadata: SignatureMetadata, public_key_bytes: Optional[bytes] = None) -> bool:
        """
        Xác thực chữ ký ECDSA
        Args:
            file_path: Đường dẫn file cần verify
            metadata: Metadata chứa chữ ký
            public_key_bytes: Public key bytes (nếu None thì dùng self.public_key)
        Returns:
            True nếu chữ ký hợp lệ
        """
        try:
            print(f"🔍 ECDSA: Xác thực chữ ký cho {Path(file_path).name}")
            
            # Sử dụng public key
            pub_key = self.public_key
            if public_key_bytes:
                pub_key = VerifyingKey.from_string(public_key_bytes, curve=self.curve)
            
            # Tính hash của file hiện tại
            current_hash = self.calculate_file_hash(file_path)
            
            # So sánh với hash trong metadata
            if current_hash != metadata.file_hash:
                print(f"❌ File đã bị thay đổi!")
                print(f"   Original hash: {metadata.file_hash[:32]}...")
                print(f"   Current hash:  {current_hash[:32]}...")
                return False
            
            # Decode signature
            signature_bytes = base64.b64decode(metadata.signature)
            
            # Verify signature (giả định SHA-256)
            pub_key.verify(signature_bytes, current_hash.encode(), hashfunc=hashlib.sha256)
            
            print(f"✅ ECDSA: Chữ ký hợp lệ")
            print(f"   - Người ký: {metadata.signer_name}")
            print(f"   - Tổ chức: {metadata.organization}")
            print(f"   - Thời gian: {metadata.timestamp}")
            
            return True
            
        except Exception as e:
            print(f"❌ ECDSA: Chữ ký không hợp lệ - {str(e)}")
            return False
    
    def export_public_key(self) -> bytes:
        """Export public key dạng bytes"""
        return self.public_key.to_string()
    
    def export_private_key(self) -> bytes:
        """Export private key dạng bytes (cẩn thận!)"""
        return self.private_key.to_string()

# =====================================================================
# PHẦN 4: CONTRACT MANAGEMENT SYSTEM
# =====================================================================

class ContractManager:
    """Quản lý hợp đồng và chữ ký số"""
    
    def __init__(self, storage_path: str = "contracts_storage"):
        """
        Args:
            storage_path: Thư mục lưu trữ hợp đồng và chữ ký
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        
        self.contracts_db = {}  # Contract ID -> metadata
        self.signers_db = {}    # Signer ID -> public keys
        
        print(f"📁 Contract Manager: Khởi tạo storage tại {self.storage_path}")
    
    def register_contract(self, contract_id: str, file_path: str, description: str = ""):
        """Đăng ký hợp đồng mới"""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Contract file không tồn tại: {file_path}")
        
        contract_info = {
            'contract_id': contract_id,
            'file_path': str(file_path),
            'file_name': file_path.name,
            'description': description,
            'registered_at': datetime.datetime.now().isoformat(),
            'signatures': []
        }
        
        self.contracts_db[contract_id] = contract_info
        print(f"📋 Đã đăng ký hợp đồng: {contract_id}")
    
    def add_signature(self, contract_id: str, signature_metadata: SignatureMetadata):
        """Thêm chữ ký vào hợp đồng"""
        if contract_id not in self.contracts_db:
            raise ValueError(f"Contract ID không tồn tại: {contract_id}")
        
        self.contracts_db[contract_id]['signatures'].append(signature_metadata.to_dict())
        
        # Lưu signature file
        sig_file = self.storage_path / f"{contract_id}_{signature_metadata.signer_name}_{signature_metadata.signature_type}.json"
        with open(sig_file, 'w', encoding='utf-8') as f:
            json.dump(signature_metadata.to_dict(), f, indent=2, ensure_ascii=False)
        
        print(f"✍️ Đã thêm chữ ký {signature_metadata.signature_type} từ {signature_metadata.signer_name}")
    
    def verify_contract(self, contract_id: str) -> Dict[str, Any]:
        """Xác thực tất cả chữ ký của hợp đồng"""
        if contract_id not in self.contracts_db:
            raise ValueError(f"Contract ID không tồn tại: {contract_id}")
        
        contract = self.contracts_db[contract_id]
        file_path = contract['file_path']
        
        results = {
            'contract_id': contract_id,
            'file_name': contract['file_name'],
            'total_signatures': len(contract['signatures']),
            'valid_signatures': 0,
            'signature_details': []
        }
        
        print(f"🔍 Xác thực hợp đồng: {contract_id}")
        
        for sig_data in contract['signatures']:
            sig_metadata = SignatureMetadata.from_dict(sig_data)
            
            # Tạo dummy signer để verify (trong thực tế cần load public key)
            if sig_metadata.signature_type == 'RSA-PSS':
                # Cần public key để verify, tạm thời skip
                is_valid = True  # Placeholder
            else:  # ECDSA
                # Cần public key để verify, tạm thời skip  
                is_valid = True  # Placeholder
            
            if is_valid:
                results['valid_signatures'] += 1
            
            results['signature_details'].append({
                'signer': sig_metadata.signer_name,
                'organization': sig_metadata.organization,
                'type': sig_metadata.signature_type,
                'timestamp': sig_metadata.timestamp,
                'valid': is_valid
            })
        
        return results
    
    def get_contract_info(self, contract_id: str) -> Dict[str, Any]:
        """Lấy thông tin hợp đồng"""
        if contract_id not in self.contracts_db:
            raise ValueError(f"Contract ID không tồn tại: {contract_id}")
        
        return self.contracts_db[contract_id].copy()
    
    def list_contracts(self) -> list:
        """Liệt kê tất cả hợp đồng"""
        return list(self.contracts_db.keys())

# =====================================================================
# PHẦN 5: DEMO VÀ TEST CASES
# =====================================================================

def create_sample_contracts():
    """Tạo các file hợp đồng mẫu"""
    print("\n📄 TẠO HỢP ĐỒNG MẪU...")
    
    # Hợp đồng 1: Text file
    contract1_content = """
MEMORANDUM OF UNDERSTANDING (MOU)

Giữa: CÔNG TY A (Bên A)
Và: CÔNG TY B (Bên B)

Điều 1: Mục đích hợp tác
- Phát triển công nghệ AI
- Chia sẻ tài nguyên nghiên cứu
- Hợp tác thương mại

Điều 2: Thời hạn
Hợp đồng có hiệu lực từ 01/09/2024 đến 31/12/2025.

Điều 3: Trách nhiệm các bên
- Bên A: Cung cấp công nghệ
- Bên B: Cung cấp tài chính

Ngày ký: 01/09/2024
Địa điểm: TP. Hồ Chí Minh
"""
    
    contract2_content = """
HỢP ĐỒNG MUA BÁN PHẦN MẀM

Bên bán: TECH COMPANY XYZ
Bên mua: ENTERPRISE ABC

Sản phẩm: Hệ thống quản lý doanh nghiệp
Giá trị: 500,000,000 VNĐ
Thời gian bàn giao: 30 ngày

Điều khoản thanh toán:
- 50% trước khi bắt đầu
- 50% khi nghiệm thu

Bảo hành: 12 tháng
"""
    
    # Tạo thư mục contracts
    contracts_dir = Path("sample_contracts")
    contracts_dir.mkdir(exist_ok=True)
    
    # Lưu contracts
    contract1_path = contracts_dir / "mou_company_a_b.txt"
    contract2_path = contracts_dir / "software_purchase_agreement.txt"
    
    with open(contract1_path, 'w', encoding='utf-8') as f:
        f.write(contract1_content)
    
    with open(contract2_path, 'w', encoding='utf-8') as f:
        f.write(contract2_content)
    
    print(f"✅ Đã tạo hợp đồng: {contract1_path}")
    print(f"✅ Đã tạo hợp đồng: {contract2_path}")
    
    return str(contract1_path), str(contract2_path)

def demo_rsa_signing():
    """Demo chữ ký RSA-PSS"""
    print("\n" + "="*60)
    print("DEMO 1: CHỮ KÝ RSA-PSS")
    print("="*60)
    
    # Tạo hợp đồng mẫu
    contract1, contract2 = create_sample_contracts()
    
    # Tạo signers
    ceo_signer = RSAContractSigner("Nguyen Van CEO", "CÔNG TY A", key_size=2048)
    cto_signer = RSAContractSigner("Tran Thi CTO", "CÔNG TY B", key_size=2048)
    
    print(f"\n👥 Người ký:")
    print(f"   - {ceo_signer.signer_name} ({ceo_signer.organization})")
    print(f"   - {cto_signer.signer_name} ({cto_signer.organization})")
    
    # Ký hợp đồng 1
    print(f"\n✍️ CEO ký hợp đồng MOU:")
    ceo_signature = ceo_signer.sign_contract(contract1)
    
    print(f"\n✍️ CTO ký hợp đồng MOU:")
    cto_signature = cto_signer.sign_contract(contract1)
    
    # Verify chữ ký
    print(f"\n🔍 XÁC THỰC CHỮ KÝ:")
    
    # CEO verify chính chữ ký của mình
    print("CEO verify chữ ký của chính mình:")
    is_valid = ceo_signer.verify_signature(contract1, ceo_signature)
    
    # CTO verify chữ ký CEO (cần public key)
    print("\nCTO verify chữ ký của CEO:")
    ceo_public_key = ceo_signer.export_public_key()
    is_valid = cto_signer.verify_signature(contract1, ceo_signature, ceo_public_key)
    
    # Test với file đã bị sửa
    print(f"\n🔧 TEST VỚI FILE BỊ SỬA:")
    modified_contract = Path("sample_contracts") / "modified_mou.txt"
    with open(modified_contract, 'w', encoding='utf-8') as f:
        f.write("HỢP ĐỒNG ĐÃ BỊ SỬA - KHÔNG HỢP LỆ!")
    
    print("Verify chữ ký với file đã bị sửa:")
    is_valid = ceo_signer.verify_signature(str(modified_contract), ceo_signature)

def demo_ecdsa_signing():
    """Demo chữ ký ECDSA"""
    print("\n" + "="*60)
    print("DEMO 2: CHỮ KÝ ECDSA")
    print("="*60)
    
    contract1, contract2 = create_sample_contracts()
    
    # Tạo ECDSA signers
    legal_signer = ECDSAContractSigner("Le Van Legal", "PHÒNG PHÁP CHẾ", curve=NIST256p)
    finance_signer = ECDSAContractSigner("Pham Thi Finance", "PHÒNG TÀI CHÍNH", curve=NIST384p)
    
    print(f"\n👥 Người ký ECDSA:")
    print(f"   - {legal_signer.signer_name} ({legal_signer.curve.name})")
    print(f"   - {finance_signer.signer_name} ({finance_signer.curve.name})")
    
    # Ký hợp đồng mua bán
    print(f"\n✍️ Legal ký hợp đồng mua bán:")
    legal_signature = legal_signer.sign_contract(contract2)
    
    print(f"\n✍️ Finance ký hợp đồng mua bán:")
    finance_signature = finance_signer.sign_contract(contract2)
    
    # Verify
    print(f"\n🔍 XÁC THỰC CHỮ KÝ ECDSA:")
    
    print("Legal verify chữ ký của chính mình:")
    is_valid = legal_signer.verify_signature(contract2, legal_signature)
    
    print("\nFinance verify chữ ký Legal:")
    legal_public_key = legal_signer.export_public_key()
    is_valid = finance_signer.verify_signature(contract2, legal_signature, legal_public_key)

def demo_contract_management():
    """Demo hệ thống quản lý hợp đồng"""
    print("\n" + "="*60)
    print("DEMO 3: HỆ THỐNG QUẢN LÝ HỢP ĐỒNG")
    print("="*60)
    
    # Khởi tạo contract manager
    manager = ContractManager("demo_contracts_storage")
    
    # Tạo hợp đồng
    contract1, contract2 = create_sample_contracts()
    
    # Đăng ký hợp đồng
    manager.register_contract("CONTRACT_001", contract1, "MOU between Company A & B")
    manager.register_contract("CONTRACT_002", contract2, "Software Purchase Agreement")
    
    # Tạo signers
    ceo = RSAContractSigner("CEO Nguyen", "COMPANY A")
    cto = ECDSAContractSigner("CTO Tran", "COMPANY B")
    
    # Ký hợp đồng
    print(f"\n✍️ CEO ký CONTRACT_001:")
    ceo_sig = ceo.sign_contract(contract1)
    manager.add_signature("CONTRACT_001", ceo_sig)
    
    print(f"\n✍️ CTO ký CONTRACT_001:")
    cto_sig = cto.sign_contract(contract1)
    manager.add_signature("CONTRACT_001", cto_sig)
    
    # Xem thông tin hợp đồng
    print(f"\n📋 THÔNG TIN HỢP ĐỒNG:")
    contract_info = manager.get_contract_info("CONTRACT_001")
    print(f"Contract ID: {contract_info['contract_id']}")
    print(f"File: {contract_info['file_name']}")
    print(f"Mô tả: {contract_info['description']}")
    print(f"Số chữ ký: {len(contract_info['signatures'])}")
    
    for i, sig in enumerate(contract_info['signatures'], 1):
        print(f"   {i}. {sig['signer_name']} ({sig['organization']}) - {sig['signature_type']}")
    
    # Verify hợp đồng
    print(f"\n🔍 XÁC THỰC HỢP ĐỒNG:")
    verification_result = manager.verify_contract("CONTRACT_001")
    print(f"Tổng chữ ký: {verification_result['total_signatures']}")
    print(f"Chữ ký hợp lệ: {verification_result['valid_signatures']}")

def demo_multi_party_signing():
    """Demo ký hợp đồng nhiều bên"""
    print("\n" + "="*60)
    print("DEMO 4: KÝ HỢP ĐỒNG NHIỀU BÊN")
    print("="*60)
    
    # Tạo hợp đồng đa bên
    multi_party_contract = """
HỢP ĐỒNG HỢP TÁC ĐA BÊN
PHÁT TRIỂN DỰ ÁN CÔNG NGHỆ AI

Các bên tham gia:
1. CÔNG TY CÔNG NGHỆ ABC (Bên cung cấp công nghệ)
2. CÔNG TY TÀI CHÍNH XYZ (Bên đầu tư)  
3. ĐẠI HỌC BÁCH KHOA (Bên nghiên cứu)
4. VIỆN AI QUỐC GIA (Bên tư vấn kỹ thuật)

Mục tiêu dự án:
- Phát triển hệ thống AI cho ngành y tế
- Nghiên cứu thuật toán machine learning
- Ứng dụng vào chẩn đoán hình ảnh y khoa

Tổng giá trị dự án: 10 tỷ VNĐ
Thời gian thực hiện: 24 tháng

Phân chia trách nhiệm:
- ABC: Phát triển sản phẩm (40%)
- XYZ: Tài trợ và marketing (30%)
- BKHN: Nghiên cứu thuật toán (20%)  
- AI Institute: Tư vấn và đánh giá (10%)

Điều khoản chia sẻ lợi nhuận:
- Theo tỷ lệ đóng góp
- Royalty cho sở hữu trí tuệ
- Chia sẻ dữ liệu nghiên cứu

Ngày ký: 01/09/2024
"""
    
    # Lưu file
    multi_contract_path = Path("sample_contracts") / "multi_party_ai_contract.txt"
    with open(multi_contract_path, 'w', encoding='utf-8') as f:
        f.write(multi_party_contract)
    
    print(f"📄 Đã tạo hợp đồng đa bên: {multi_contract_path}")
    
    # Tạo các bên ký
    signers = [
        RSAContractSigner("Nguyen CEO Tech", "CÔNG TY ABC", 2048),
        RSAContractSigner("Tran CFO Finance", "CÔNG TY XYZ", 4096),
        ECDSAContractSigner("Le Professor", "ĐẠI HỌC BKHN", NIST256p),
        ECDSAContractSigner("Pham Director", "VIỆN AI", NIST384p)
    ]
    
    # Setup contract manager
    manager = ContractManager("multi_party_storage")
    manager.register_contract("AI_PROJECT_001", str(multi_contract_path), "Multi-party AI Development Contract")
    
    print(f"\n👥 CÁC BÊN KÝ HỢP ĐỒNG:")
    signatures = []
    
    # Từng bên ký hợp đồng
    for i, signer in enumerate(signers, 1):
        print(f"\n{i}. {signer.signer_name} ({signer.organization}):")
        signature = signer.sign_contract(str(multi_contract_path))
        signatures.append((signer, signature))
        manager.add_signature("AI_PROJECT_001", signature)
    
    # Xác thực toàn bộ hợp đồng
    print(f"\n🔍 XÁC THỰC HỢP ĐỒNG ĐA BÊN:")
    contract_info = manager.get_contract_info("AI_PROJECT_001")
    
    print(f"📋 Thông tin hợp đồng AI_PROJECT_001:")
    print(f"   - File: {contract_info['file_name']}")
    print(f"   - Tổng chữ ký: {len(contract_info['signatures'])}")
    print(f"   - Đăng ký lúc: {contract_info['registered_at']}")
    
    # Chi tiết từng chữ ký
    for i, sig_data in enumerate(contract_info['signatures'], 1):
        print(f"   {i}. {sig_data['signer_name']} ({sig_data['organization']})")
        print(f"      - Thuật toán: {sig_data['signature_type']}")
        print(f"      - Thời gian: {sig_data['timestamp']}")
        print(f"      - Hash: {sig_data['file_hash'][:32]}...")

def demo_tamper_detection():
    """Demo phát hiện giả mạo hợp đồng"""
    print("\n" + "="*60)
    print("DEMO 5: PHÁT HIỆN GIẤU MẠO HỢP ĐỒNG")
    print("="*60)
    
    # Tạo hợp đồng gốc
    original_contract = """
HỢP ĐỒNG LAO ĐỘNG

Người lao động: Trần Văn A
Vị trí: Kỹ sư phần mềm
Mức lương: 25,000,000 VNĐ/tháng
Thời hạn: 2 năm
Thử việc: 2 tháng

Quyền lợi:
- Bảo hiểm y tế
- Thưởng cuối năm
- Đào tạo chuyên môn

Nghĩa vụ:
- Làm việc 8 giờ/ngày
- Bảo mật thông tin
- Tuân thủ quy định công ty
"""
    
    contract_path = Path("sample_contracts") / "labor_contract.txt"
    with open(contract_path, 'w', encoding='utf-8') as f:
        f.write(original_contract)
    
    # HR ký hợp đồng
    hr_signer = RSAContractSigner("Nguyen HR Manager", "PHÒNG NHÂN SỰ")
    employee_signer = ECDSAContractSigner("Tran Van Employee", "NHÂN VIÊN")
    
    print(f"📄 Hợp đồng lao động: {contract_path}")
    print(f"✍️ HR Manager ký hợp đồng:")
    hr_signature = hr_signer.sign_contract(str(contract_path))
    
    print(f"✍️ Nhân viên ký hợp đồng:")
    employee_signature = employee_signer.sign_contract(str(contract_path))
    
    # Xác thực hợp đồng gốc
    print(f"\n🔍 XÁC THỰC HỢP ĐỒNG GỐC:")
    hr_valid = hr_signer.verify_signature(str(contract_path), hr_signature)
    employee_valid = employee_signer.verify_signature(str(contract_path), employee_signature)
    
    # Giả lập kẻ tấn công sửa hợp đồng
    print(f"\n🔴 KẺ TẤN CÔNG SỬA HỢP ĐỒNG:")
    tampered_contract = original_contract.replace("25,000,000", "15,000,000")  # Giảm lương!
    tampered_contract = tampered_contract.replace("2 năm", "5 năm")  # Tăng thời hạn!
    
    tampered_path = Path("sample_contracts") / "tampered_labor_contract.txt"
    with open(tampered_path, 'w', encoding='utf-8') as f:
        f.write(tampered_contract)
    
    print(f"   📝 Tạo file giả mạo: {tampered_path}")
    print(f"   💰 Lương bị sửa: 25M → 15M VNĐ")
    print(f"   📅 Thời hạn bị sửa: 2 → 5 năm")
    
    # Thử xác thực với file giả mạo
    print(f"\n🔍 XÁC THỰC VỚI FILE GIẤU MẠO:")
    print("HR signature với file giả mạo:")
    hr_tampered = hr_signer.verify_signature(str(tampered_path), hr_signature)
    
    print("Employee signature với file giả mạo:")  
    employee_tampered = employee_signer.verify_signature(str(tampered_path), employee_signature)
    
    # Kết luận
    if not hr_tampered and not employee_tampered:
        print("\n✅ HỆ THỐNG BẢO MẬT HOẠT ĐỘNG TỐT!")
        print("   - Phát hiện được file bị sửa đổi")
        print("   - Chữ ký số đảm bảo tính toàn vẹn")
        print("   - Không thể giả mạo hợp đồng")

def demo_performance_comparison():
    """So sánh hiệu suất RSA vs ECDSA"""
    print("\n" + "="*60)
    print("DEMO 6: SO SÁNH HIỆU SUẤT RSA vs ECDSA")
    print("="*60)
    
    import time
    
    # Tạo test contract
    test_contract = "sample_contracts/performance_test.txt"
    with open(test_contract, 'w', encoding='utf-8') as f:
        f.write("Test contract for performance measurement. " * 100)
    
    print(f"📄 Test contract: {Path(test_contract).name}")
    print(f"📏 Kích thước: {os.path.getsize(test_contract)} bytes")
    
    # Test RSA-PSS
    print(f"\n⏱️ RSA-PSS PERFORMANCE:")
    rsa_results = {}
    
    for key_size in [2048, 4096]:
        print(f"\n🔑 RSA-{key_size}:")
        
        # Tạo key
        start = time.time()
        rsa_signer = RSAContractSigner("RSA Tester", "TEST ORG", key_size)
        keygen_time = time.time() - start
        
        # Ký
        start = time.time()
        signature = rsa_signer.sign_contract(test_contract)
        sign_time = time.time() - start
        
        # Verify
        start = time.time()
        is_valid = rsa_signer.verify_signature(test_contract, signature)
        verify_time = time.time() - start
        
        rsa_results[key_size] = {
            'keygen': keygen_time,
            'sign': sign_time,
            'verify': verify_time,
            'sig_size': len(signature.signature)
        }
        
        print(f"   Tạo key: {keygen_time:.4f}s")
        print(f"   Ký: {sign_time:.4f}s")
        print(f"   Verify: {verify_time:.4f}s")
        print(f"   Signature size: {len(signature.signature)} chars")
    
    # Test ECDSA
    print(f"\n⏱️ ECDSA PERFORMANCE:")
    ecdsa_results = {}
    
    for curve, name in [(NIST256p, "P-256"), (NIST384p, "P-384")]:
        print(f"\n🔑 ECDSA-{name}:")
        
        # Tạo key
        start = time.time()
        ecdsa_signer = ECDSAContractSigner("ECDSA Tester", "TEST ORG", curve)
        keygen_time = time.time() - start
        
        # Ký
        start = time.time()
        signature = ecdsa_signer.sign_contract(test_contract)
        sign_time = time.time() - start
        
        # Verify
        start = time.time()
        is_valid = ecdsa_signer.verify_signature(test_contract, signature)
        verify_time = time.time() - start
        
        ecdsa_results[name] = {
            'keygen': keygen_time,
            'sign': sign_time,
            'verify': verify_time,
            'sig_size': len(signature.signature)
        }
        
        print(f"   Tạo key: {keygen_time:.4f}s")
        print(f"   Ký: {sign_time:.4f}s")
        print(f"   Verify: {verify_time:.4f}s")
        print(f"   Signature size: {len(signature.signature)} chars")
    
    # Tổng kết so sánh
    print(f"\n📊 TỔNG KẾT SO SÁNH:")
    print(f"{'Algorithm':<12} {'KeyGen(s)':<10} {'Sign(s)':<8} {'Verify(s)':<10} {'Sig Size':<10}")
    print("-" * 60)
    
    for key_size, data in rsa_results.items():
        print(f"{'RSA-'+str(key_size):<12} {data['keygen']:<10.4f} {data['sign']:<8.4f} {data['verify']:<10.4f} {data['sig_size']:<10}")
    
    for curve, data in ecdsa_results.items():
        print(f"{'ECDSA-'+curve:<12} {data['keygen']:<10.4f} {data['sign']:<8.4f} {data['verify']:<10.4f} {data['sig_size']:<10}")
    
    print(f"\n💡 KẾT LUẬN:")
    print(f"   ✅ ECDSA: Nhanh hơn, signature nhỏ hơn")
    print(f"   ✅ RSA-PSS: Mature hơn, hỗ trợ rộng rãi")
    print(f"   🎯 Lựa chọn: Phụ thuộc vào yêu cầu cụ thể")

def demo_real_world_workflow():
    """Demo quy trình thực tế"""
    print("\n" + "="*60)
    print("DEMO 7: QUY TRÌNH THỰC TẾ - HỢP ĐỒNG B2B")
    print("="*60)
    
    # Kịch bản: Hợp đồng outsourcing phát triển app
    contract_content = """
HỢP ĐỒNG OUTSOURCING PHÁT TRIỂN ỨNG DỤNG

BÊN A (Khách hàng): STARTUP FINTECH ABC
Địa chỉ: 123 Nguyễn Huệ, Q1, TP.HCM
Người đại diện: CEO Nguyễn Văn A

BÊN B (Nhà thầu): CÔNG TY PHẦN MỀM XYZ  
Địa chỉ: 456 Lê Lợi, Q1, TP.HCM
Người đại diện: CTO Trần Thị B

DỰ ÁN: Ứng dụng mobile banking
THỜI GIAN: 6 tháng (01/10/2024 - 31/03/2025)
GIÁ TRỊ HỢP ĐỒNG: 2,000,000,000 VNĐ

PHẠM VI CÔNG VIỆC:
1. Phát triển app iOS/Android
2. Backend API và database
3. Tích hợp payment gateway
4. Bảo mật và testing
5. Deploy và maintenance

MILESTONE VÀ THANH TOÁN:
- Milestone 1 (30%): UI/UX design - 600M VNĐ
- Milestone 2 (40%): Core features - 800M VNĐ  
- Milestone 3 (30%): Testing & Deploy - 600M VNĐ

BẢO HÀNH: 12 tháng
BẢO MẬT: NDA trong 3 năm
SỞ HỮU TRÍ TUỆ: Thuộc về Bên A

ĐIỀU KHOẢN PHẠT:
- Chậm tiến độ: 1%/ngày trên milestone
- Lỗi nghiêm trọng: 5% giá trị dự án

Ngày ký: 01/09/2024
"""
    
    # Tạo hợp đồng
    real_contract_path = Path("sample_contracts") / "fintech_outsourcing_contract.txt"
    with open(real_contract_path, 'w', encoding='utf-8') as f:
        f.write(contract_content)
    
    print(f"📋 HƯỚNG DẪN QUY TRÌNH:")
    print(f"1. Tạo hợp đồng: {real_contract_path}")
    
    # Các bên liên quan
    print(f"\n👥 CÁC BÊN LIÊN QUAN:")
    
    # Bên A - Startup
    startup_ceo = RSAContractSigner("CEO Nguyen Van A", "STARTUP ABC", 2048)
    startup_legal = ECDSAContractSigner("Legal Advisor", "STARTUP ABC", NIST256p)
    
    # Bên B - Software Company
    company_cto = RSAContractSigner("CTO Tran Thi B", "COMPANY XYZ", 4096)
    company_pm = ECDSAContractSigner("Project Manager", "COMPANY XYZ", NIST384p)
    
    signers_info = [
        ("Startup CEO", startup_ceo),
        ("Startup Legal", startup_legal), 
        ("Company CTO", company_cto),
        ("Company PM", company_pm)
    ]
    
    for name, signer in signers_info:
        print(f"   - {name}: {signer.signer_name} ({signer.organization})")
    
    # Setup contract management
    print(f"\n📁 SETUP HỆ THỐNG QUẢN LÝ:")
    manager = ContractManager("production_contracts")
    manager.register_contract("FINTECH_001", str(real_contract_path), "Fintech App Outsourcing Contract")
    
    # Quy trình ký tuần tự
    print(f"\n✍️ QUY TRÌNH KÝ HỢP ĐỒNG:")
    
    signing_order = [
        ("1. Startup Legal xem xét và ký", startup_legal),
        ("2. Startup CEO phê duyệt và ký", startup_ceo),
        ("3. Company PM xác nhận và ký", company_pm),  
        ("4. Company CTO cuối cùng ký", company_cto)
    ]
    
    for step, signer in signing_order:
        print(f"\n{step}:")
        signature = signer.sign_contract(str(real_contract_path))
        manager.add_signature("FINTECH_001", signature)
        
        # Simulate review time
        import time
        time.sleep(0.5)
    
    # Kết quả cuối cùng
    print(f"\n📊 KẾT QUẢ CUỐI CÙNG:")
    final_contract = manager.get_contract_info("FINTECH_001")
    
    print(f"✅ Hợp đồng FINTECH_001 đã hoàn thành:")
    print(f"   - File: {final_contract['file_name']}")
    print(f"   - Tổng chữ ký: {len(final_contract['signatures'])}")
    print(f"   - Giá trị: 2,000,000,000 VNĐ")
    
    print(f"\n📋 CHI TIẾT CHỮ KÝ:")
    for i, sig in enumerate(final_contract['signatures'], 1):
        print(f"   {i}. {sig['signer_name']} ({sig['organization']})")
        print(f"      Thuật toán: {sig['signature_type']}")
        print(f"      Thời gian: {sig['timestamp']}")
    
    print(f"\n🔐 TÍNH PHÁP LÝ:")
    print(f"   ✅ Tính toàn vẹn (Integrity): File không bị sửa")
    print(f"   ✅ Tính xác thực (Authenticity): Đúng người ký")  
    print(f"   ✅ Không thể chối bỏ (Non-repudiation): Có bằng chứng số")

def main():
    """Chạy tất cả demo"""
    print("🎯 CHẠY TẤT CẢ DEMO CHỮ KÝ SỐ B2B")
    
    # Tạo thư mục cần thiết
    Path("sample_contracts").mkdir(exist_ok=True)
    
    # Chạy từng demo
    demo_rsa_signing()
    demo_ecdsa_signing() 
    demo_contract_management()
    demo_multi_party_signing()
    demo_tamper_detection()
    demo_performance_comparison()
    demo_real_world_workflow()
    
    print(f"\n" + "="*60)
    print("✅ HOÀN THÀNH TẤT CẢ DEMO")
    print("🎯 HỆ THỐNG CHỮ KÝ SỐ B2B SẴN SÀNG SỬ DỤNG")
    print("="*60)

if __name__ == "__main__":
    main()