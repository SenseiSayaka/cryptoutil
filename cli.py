#!/usr/bin/env python3
"""
Криптографическая утилита - CLI интерфейс (ИСПРАВЛЕННАЯ ВЕРСИЯ)
"""
import click
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
from getpass import getpass

from src import (
    AESCipher, ChaCha20Cipher, StreamCipher,
    RSACrypto, Ed25519Crypto,
    HashManager, calculate_file_hash, verify_file_integrity,
    SignatureManager,
    HybridCrypto, StreamHybridCrypto,
    CryptoUtils, FileProcessor,
    __version__
)

console = Console()


# ============================================================================
# ГЛАВНАЯ ГРУППА КОМАНД
# ============================================================================

@click.group()
@click.version_option(version=__version__, prog_name="CryptoUtil")
def cli():
    """
    🔐 Криптографическая утилита
    
    Полный набор инструментов для шифрования, подписи и хеширования файлов.
    """
    pass


# ============================================================================
# СИММЕТРИЧНОЕ ШИФРОВАНИЕ (ИСПРАВЛЕНО)
# ============================================================================

@cli.group()
def symmetric():
    """Симметричное шифрование (AES, ChaCha20)"""
    pass


@symmetric.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.argument('output_file', type=click.Path())
@click.option('-a', '--algorithm', type=click.Choice(['AES', 'ChaCha20']), 
              default='AES', help='Алгоритм шифрования')
@click.option('-p', '--password', is_flag=True, help='Использовать пароль вместо ключа')
@click.option('-k', '--key-file', type=click.Path(exists=True), help='Файл с ключом')
@click.option('--stream', is_flag=True, help='Потоковая обработка для больших файлов')
def encrypt(input_file, output_file, algorithm, password, key_file, stream):
    """Шифрование файла симметричным алгоритмом"""
    try:
        console.print(f"[cyan]🔐 Шифрование {input_file}...[/cyan]")
        
        # Получаем ключ
        if password:
            pwd = getpass("Введите пароль: ")
            pwd_confirm = getpass("Подтвердите пароль: ")
            
            if pwd != pwd_confirm:
                console.print("[red]❌ Пароли не совпадают![/red]")
                sys.exit(1)
            
            # Создаем шифр из пароля
            cipher_class = AESCipher if algorithm == 'AES' else ChaCha20Cipher
            cipher, salt = cipher_class.from_password(pwd)
            
            # Читаем и шифруем файл
            with open(input_file, 'rb') as f:
                plaintext = f.read()
            
            console.print("[cyan]   Шифрование данных...[/cyan]")
            ciphertext = cipher.encrypt(plaintext)
            
            # Сохраняем соль + зашифрованные данные
            with open(output_file, 'wb') as f:
                f.write(salt)
                f.write(ciphertext)
            
        elif key_file:
            key = CryptoUtils.load_from_file(key_file)
            cipher_class = AESCipher if algorithm == 'AES' else ChaCha20Cipher
            
            if stream:
                console.print("[cyan]   Потоковое шифрование...[/cyan]")
                stream_cipher = StreamCipher(cipher_class, key)
                stream_cipher.encrypt_file(input_file, output_file)
            else:
                cipher = cipher_class(key)
                with open(input_file, 'rb') as f:
                    plaintext = f.read()
                console.print("[cyan]   Шифрование данных...[/cyan]")
                ciphertext = cipher.encrypt(plaintext)
                CryptoUtils.save_to_file(output_file, ciphertext)
        else:
            # Генерируем новый ключ
            console.print("[cyan]   Генерация ключа...[/cyan]")
            key = CryptoUtils.generate_random_bytes(32)
            key_output = f"{output_file}.key"
            CryptoUtils.save_to_file(key_output, key)
            
            cipher_class = AESCipher if algorithm == 'AES' else ChaCha20Cipher
            
            if stream:
                console.print("[cyan]   Потоковое шифрование...[/cyan]")
                stream_cipher = StreamCipher(cipher_class, key)
                stream_cipher.encrypt_file(input_file, output_file)
            else:
                cipher = cipher_class(key)
                with open(input_file, 'rb') as f:
                    plaintext = f.read()
                console.print("[cyan]   Шифрование данных...[/cyan]")
                ciphertext = cipher.encrypt(plaintext)
                CryptoUtils.save_to_file(output_file, ciphertext)
            
            console.print(f"[green]🔑 Ключ сохранён в: {key_output}[/green]")
        
        console.print(f"[green]✅ Файл зашифрован: {output_file}[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Ошибка: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@symmetric.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.argument('output_file', type=click.Path())
@click.option('-a', '--algorithm', type=click.Choice(['AES', 'ChaCha20']), 
              default='AES', help='Алгоритм шифрования')
@click.option('-p', '--password', is_flag=True, help='Использовать пароль')
@click.option('-k', '--key-file', type=click.Path(exists=True), help='Файл с ключом')
@click.option('--stream', is_flag=True, help='Потоковая обработка')
def decrypt(input_file, output_file, algorithm, password, key_file, stream):
    """Расшифровка файла"""
    try:
        console.print(f"[cyan]🔓 Расшифровка {input_file}...[/cyan]")
        
        if password:
            pwd = getpass("Введите пароль: ")
            
            # Читаем соль и зашифрованные данные
            with open(input_file, 'rb') as f:
                salt = f.read(16)
                ciphertext = f.read()
            
            cipher_class = AESCipher if algorithm == 'AES' else ChaCha20Cipher
            cipher, _ = cipher_class.from_password(pwd, salt)
            
            console.print("[cyan]   Расшифровка данных...[/cyan]")
            plaintext = cipher.decrypt(ciphertext)
            
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            
        elif key_file:
            key = CryptoUtils.load_from_file(key_file)
            cipher_class = AESCipher if algorithm == 'AES' else ChaCha20Cipher
            
            if stream:
                console.print("[cyan]   Потоковая расшифровка...[/cyan]")
                stream_cipher = StreamCipher(cipher_class, key)
                stream_cipher.decrypt_file(input_file, output_file)
            else:
                cipher = cipher_class(key)
                ciphertext = CryptoUtils.load_from_file(input_file)
                console.print("[cyan]   Расшифровка данных...[/cyan]")
                plaintext = cipher.decrypt(ciphertext)
                CryptoUtils.save_to_file(output_file, plaintext)
        else:
            console.print("[red]❌ Необходимо указать --password или --key-file[/red]")
            sys.exit(1)
        
        console.print(f"[green]✅ Файл расшифрован: {output_file}[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Ошибка расшифровки: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


@symmetric.command()
@click.option('-o', '--output', type=click.Path(), help='Файл для сохранения ключа')
def generate_key(output):
    """Генерация случайного ключа"""
    console.print("[cyan]🔑 Генерация ключа...[/cyan]")
    key = CryptoUtils.generate_random_bytes(32)
    
    if output:
        CryptoUtils.save_to_file(output, key)
        console.print(f"[green]✅ Ключ сохранён: {output}[/green]")
    else:
        console.print(f"[cyan]Ключ (hex): {key.hex()}[/cyan]")
        console.print(f"[yellow]⚠️  Сохраните ключ в безопасном месте![/yellow]")


# ============================================================================
# ХЕШИРОВАНИЕ (УПРОЩЕНО)
# ============================================================================

@cli.group()
def hash():
    """Хеширование и проверка целостности файлов"""
    pass


@hash.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('-a', '--algorithm', 
              type=click.Choice(['sha256', 'sha512', 'blake2', 'sha3-256', 'sha3-512']),
              default='sha256', help='Алгоритм хеширования')
@click.option('-o', '--output', type=click.Path(), help='Сохранить хеш в файл')
def compute(file, algorithm, output):
    """Вычисление хеша файла"""
    try:
        console.print(f"[cyan]#️⃣  Вычисление {algorithm.upper()} хеша...[/cyan]")
        
        file_hash = calculate_file_hash(file, algorithm)
        
        # Создаем красивую таблицу
        table = Table(title=f"Хеш файла: {file}")
        table.add_column("Алгоритм", style="cyan")
        table.add_column("Хеш", style="green")
        table.add_row(algorithm.upper(), file_hash)
        
        console.print(table)
        
        if output:
            with open(output, 'w') as f:
                f.write(f"{file_hash}  {Path(file).name}\n")
            console.print(f"[green]✅ Хеш сохранён: {output}[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Ошибка: {e}[/red]")
        sys.exit(1)


@hash.command()
@click.argument('file', type=click.Path(exists=True))
@click.argument('expected_hash', type=str)
@click.option('-a', '--algorithm', 
              type=click.Choice(['sha256', 'sha512', 'blake2', 'sha3-256', 'sha3-512']),
              default='sha256', help='Алгоритм хеширования')
def verify(file, expected_hash, algorithm):
    """Проверка хеша файла"""
    try:
        console.print(f"[cyan]🔍 Проверка целостности...[/cyan]")
        
        is_valid = verify_file_integrity(file, expected_hash, algorithm)
        
        if is_valid:
            console.print(f"[green]✅ Хеш совпадает! Файл не изменён.[/green]")
        else:
            console.print(f"[red]❌ Хеш НЕ совпадает! Файл изменён или повреждён.[/red]")
            sys.exit(1)
        
    except Exception as e:
        console.print(f"[red]❌ Ошибка: {e}[/red]")
        sys.exit(1)


# ============================================================================
# ИНФОРМАЦИЯ
# ============================================================================

@cli.command()
def info():
    """Информация о доступных алгоритмах"""
    
    panel = Panel.fit(
        "[bold cyan]Криптографическая утилита[/bold cyan]\n"
        f"Версия: {__version__}\n\n"
        "Полный набор инструментов для криптографии",
        border_style="cyan"
    )
    console.print(panel)
    
    # Симметричное шифрование
    table1 = Table(title="🔐 Симметричное шифрование", show_header=True)
    table1.add_column("Алгоритм", style="cyan")
    table1.add_column("Описание", style="white")
    table1.add_column("Рекомендация", style="green")
    
    table1.add_row(
        "AES-256-GCM",
        "Advanced Encryption Standard с аутентификацией",
        "✅ Рекомендуется"
    )
    table1.add_row(
        "ChaCha20-Poly1305",
        "Современный потоковый шифр",
        "✅ Рекомендуется"
    )
    
    console.print(table1)


@cli.command()
def examples():
    """Примеры использования"""
    
    examples_text = """
[bold cyan]📚 Примеры использования[/bold cyan]

[yellow]1. Симметричное шифрование с паролем:[/yellow]
   python cli.py symmetric encrypt document.pdf document.pdf.enc -p
   python cli.py symmetric decrypt document.pdf.enc document.pdf -p

[yellow]2. Симметричное шифрование с ключом:[/yellow]
   python cli.py symmetric generate-key -o my.key
   python cli.py symmetric encrypt data.txt data.enc -k my.key
   python cli.py symmetric decrypt data.enc data.txt -k my.key

[yellow]3. Вычисление хеша файла:[/yellow]
   python cli.py hash compute file.iso -a sha256
   
[yellow]4. Проверка хеша:[/yellow]
   python cli.py hash verify file.iso <hash> -a sha256

[yellow]5. Информация:[/yellow]
   python cli.py info
"""
    
    console.print(Panel(examples_text, border_style="green", expand=False))


if __name__ == '__main__':
    cli()