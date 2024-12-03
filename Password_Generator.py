import random
import string
import hashlib
import requests

# Константы
HAVE_I_BEEN_PWNED_API = "https://api.pwnedpasswords.com/range/"

def generate_password(length=12):
    """
    Генерирует безопасный пароль.
    """
    if length < 8:
        raise ValueError("Длина пароля должна быть не менее 8 символов.")
    characters = string.ascii_letters + string.digits + string.punctuation
    password = "".join(random.choice(characters) for _ in range(length))
    return password

def check_password_leak(password):
    """
    Проверяет, есть ли пароль в утечках данных.
    Использует K-Anonymity через API Have I Been Pwned.
    """
    # Вычисляем SHA-1 хэш пароля
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    response = requests.get(HAVE_I_BEEN_PWNED_API + prefix)
    response.raise_for_status()
    hashes = (line.split(":") for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if suffix == hash_suffix:
            return True, int(count)
    return False, 0

def main():
    print("=== Генератор и проверка паролей ===")
    length = int(input("Введите длину пароля (не менее 8): "))
    password = generate_password(length)
    print(f"Сгенерированный пароль: {password}")
    
    print("Проверка пароля на утечки...")
    is_leaked, count = check_password_leak(password)
    if is_leaked:
        print(f"⚠️ Пароль найден в утечках данных {count} раз(а). Используйте другой пароль!")
    else:
        print("✅ Пароль не найден в утечках данных. Используйте его с уверенностью!")

if __name__ == "__main__":
    main()

