from app import *
from app.import_files import *
import pytest


class TestEncryptUrl:

    #  Encrypts a valid URL string
    def test_encrypts_valid_url_string(self):
        url = "https://www.example.com"
        encrypted_url = encrypt_url(url)
        assert isinstance(encrypted_url, str)
        assert encrypted_url != url

    #  Returns an encrypted URL string
    def test_returns_encrypted_url_string(self):
        url = "https://www.example.com"
        encrypted_url = encrypt_url(url)
        assert isinstance(encrypted_url, str)

    #  Returns an error if URL is empty
    def test_returns_error_if_url_empty(self):
        url = ""
        with pytest.raises(ValueError):
            encrypt_url(url)

    #  Returns an error if URL is not a string
    def test_returns_error_if_url_not_string(self):
        url = 12345
        with pytest.raises(AttributeError):
            encrypt_url(url)

    #  Handles non-ASCII characters in URL
    def test_handles_non_ascii_characters_in_url(self):
        url = "https://www.éxample.com"
        encrypted_url = encrypt_url(url)
        assert isinstance(encrypted_url, str)

    #  Handles special characters in URL
    def test_handles_special_characters_in_url(self):
        url = "https://www.example.com/?param=value&param2=value2"
        encrypted_url = encrypt_url(url)
        assert isinstance(encrypted_url, str)


class TestDecryptUrl:

    #  Decrypts a valid encrypted URL and returns the decrypted URL.
    def test_decrypt_valid_url(self):
        encrypted_url = fernet.encrypt(b'https://www.example.com').decode()
        decrypted_url = decrypt_url(encrypted_url)
        assert decrypted_url == 'https://www.example.com'

    #  Decrypts an empty string and returns an empty string.
    def test_decrypt_empty_string(self):
        encrypted_url = fernet.encrypt(b'').decode()
        decrypted_url = decrypt_url(encrypted_url)
        assert decrypted_url == ''

    #  Raises a TypeError if the input is not a string.
    def test_raise_type_error(self):
        with pytest.raises(TypeError):
            decrypt_url(123)

    #  Raises a ValueError if the input is an empty string.
    def test_raise_value_error(self):
        with pytest.raises(ValueError):
            decrypt_url('')

    #  Raises a cryptography.fernet.InvalidToken error if the input is not a valid encrypted URL.
    def test_raise_invalid_token_error(self):
        with pytest.raises(InvalidToken):
            decrypt_url('invalid_token')

    #  Decrypts a URL with special characters and returns the decrypted URL.
    def test_decrypt_special_characters(self):
        encrypted_url = fernet.encrypt(b'https://www.example.com/?q=python&lang=en').decode()
        decrypted_url = decrypt_url(encrypted_url)
        assert decrypted_url == 'https://www.example.com/?q=python&lang=en'


class TestGenerateFilename:

    #  Returns a string of length 10
    def test_returns_string_of_length_10(self):
        filename = generate_filename()
        assert len(filename) == 10

    #  Contains only letters and digits
    def test_contains_only_letters_and_digits(self):
        filename = generate_filename()
        assert filename.isalnum()

    #  None
    def test_none(self):
        filename = generate_filename()
        assert filename is not None

    #  Multiple calls return different strings
    def test_multiple_calls_return_different_strings(self):
        filename1 = generate_filename()
        filename2 = generate_filename()
        assert filename1 != filename2

    #  Can be used as a file name
    def test_can_be_used_as_file_name(self):
        filename = generate_filename()
        assert isinstance(filename, str)

    #  Can be used as a unique identifier
    def test_can_be_used_as_unique_identifier(self):
        filename = generate_filename()
        assert isinstance(filename, str)



class TestHashPassword:

    #  Returns a hashed password for a given input password.
    def test_returns_hashed_password(self):
        password = "password123"
        hashed_password = hash_password(password).decode('utf-8')
        assert isinstance(hashed_password, str)
        assert len(hashed_password) == 60

    #  Returns a different hashed password for the same input password on subsequent calls.
    def test_returns_different_hashed_password(self):
        password = "password123"
        hashed_password_1 = hash_password(password)
        hashed_password_2 = hash_password(password)
        assert hashed_password_1 != hashed_password_2

    #  Returns a hashed password of length 60.
    def test_returns_hashed_password_length_60(self):
        password = "password123"
        hashed_password = hash_password(password)
        assert len(hashed_password) == 60

    #  Returns a ValueError if the input password is None.
    def test_returns_value_error_if_input_password_is_none(self):
        with pytest.raises(ValueError):
            hash_password(None)

    #  Returns a TypeError if the input password is not a string.
    def test_returns_type_error_if_input_password_is_not_string(self):
        with pytest.raises(TypeError):
            hash_password(123)

    #  Returns a TypeError if the input password is an empty string.
    def test_returns_type_error_if_input_password_is_empty_string(self):
        with pytest.raises(TypeError):
            hash_password("")



class TestGenerateVerificationToken:

    #  Returns a string of length 43
    def test_returns_string_of_length_43(self):
        token = generate_verification_token()
        assert len(token) == 43

    #  Returns a string containing only URL-safe characters
    def test_returns_string_with_url_safe_characters(self):
        token = generate_verification_token()
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   for c in token)

    #  None
    def test_none(self):
        token = generate_verification_token()
        assert token is not None

    #  Returns a different string on each call
    def test_returns_different_string_on_each_call(self):
        token1 = generate_verification_token()
        token2 = generate_verification_token()
        assert token1 != token2

    #  Can generate a large number of tokens without duplicates
    def test_generate_large_number_of_tokens_without_duplicates(self):
        tokens = set()
        for _ in range(1000):
            token = generate_verification_token()
            assert token not in tokens
            tokens.add(token)

    #  Can handle concurrent requests without generating duplicate tokens
    def test_handle_concurrent_requests_without_duplicates(self):
        tokens = set()
        for _ in range(1000):
            token = generate_verification_token()
            assert token not in tokens
            tokens.add(token)



