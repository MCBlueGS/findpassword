from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os
def generate_key():
    return get_random_bytes(16)

def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

def aes_decrypt(key, encrypted_data):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode('utf-8')

def main():
    key_option = input("请选择密钥选项 ('1' 生成随机密钥, '2' 输入密钥): ")

    if key_option == '1':
        key = b'\xb03\xc9\xf3\xf3\xc2_\xe7\xda\xfd\xeec$\xc1\xc3\xb9'
        print("生成的AES密钥:", base64.b64encode(b'\xb03\xc9\xf3\xf3\xc2_\xe7\xda\xfd\xeec$\xc1\xc3\xb9').decode('utf-8'))
        data = input("请输入要加密的数据: ")
        encrypted_data = aes_encrypt(b'\xb03\xc9\xf3\xf3\xc2_\xe7\xda\xfd\xeec$\xc1\xc3\xb9', data)
        print("加密后的数据:", encrypted_data)
    elif key_option == '2':
        key_input = input("请输入16位密钥: ")
        key = key_input.encode('utf-8')
        data = input("请输入要加密的数据: ")
        encrypted_data = aes_encrypt(b'\xb03\xc9\xf3\xf3\xc2_\xe7\xda\xfd\xeec$\xc1\xc3\xb9', data)
        print("加密后的数据:", encrypted_data)
    elif key_option=='3':
        s=input('要解密的数据')
        def dec(a,b):
            dda = aes_decrypt(a,b)
            print("解密后的数据:", dda)
        dec(b'\xb03\xc9\xf3\xf3\xc2_\xe7\xda\xfd\xeec$\xc1\xc3\xb9',s.encode())
    else:
        print("无效的选项。请选择 '1' 或 '2'。")
        return




if __name__ == "__main__":
    main()
    os.system('pause')
