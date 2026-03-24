package utils

import (
	"os"
	"testing"
)

func TestTokenEncryptor(t *testing.T) {
	// Set up test environment
	os.Setenv("TOKEN_ENCRYPTION_KEY", "test-encryption-key-32-bytes-long!")
	defer os.Unsetenv("TOKEN_ENCRYPTION_KEY")

	t.Run("NewTokenEncryptor_Success", func(t *testing.T) {
		encryptor, err := NewTokenEncryptor()
		if err != nil {
			t.Fatalf("Failed to create TokenEncryptor: %v", err)
		}
		if encryptor == nil {
			t.Fatal("TokenEncryptor should not be nil")
		}
	})

	t.Run("NewTokenEncryptor_MissingKey", func(t *testing.T) {
		os.Unsetenv("TOKEN_ENCRYPTION_KEY")
		defer os.Setenv("TOKEN_ENCRYPTION_KEY", "test-encryption-key-32-bytes-long!")

		_, err := NewTokenEncryptor()
		if err == nil {
			t.Fatal("Expected error when TOKEN_ENCRYPTION_KEY is missing")
		}
	})

	t.Run("EncryptDecrypt_Success", func(t *testing.T) {
		encryptor, _ := NewTokenEncryptor()

		plaintext := "xoxb-slack-bot-token-12345"
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		if ciphertext == plaintext {
			t.Fatal("Ciphertext should be different from plaintext")
		}

		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if decrypted != plaintext {
			t.Fatalf("Decrypted text mismatch: got %s, want %s", decrypted, plaintext)
		}
	})

	t.Run("EncryptDecrypt_EmptyString", func(t *testing.T) {
		encryptor, _ := NewTokenEncryptor()

		plaintext := ""
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Failed to encrypt empty string: %v", err)
		}

		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt empty string: %v", err)
		}

		if decrypted != plaintext {
			t.Fatalf("Decrypted text mismatch: got %s, want %s", decrypted, plaintext)
		}
	})

	t.Run("EncryptDecrypt_LongToken", func(t *testing.T) {
		encryptor, _ := NewTokenEncryptor()

		plaintext := "xoxb-12345678901234567890123456789012345678901234567890-very-long-token-with-special-chars-!@#$%^&*()"
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Failed to encrypt long token: %v", err)
		}

		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt long token: %v", err)
		}

		if decrypted != plaintext {
			t.Fatalf("Decrypted text mismatch: got %s, want %s", decrypted, plaintext)
		}
	})

	t.Run("Decrypt_InvalidCiphertext", func(t *testing.T) {
		encryptor, _ := NewTokenEncryptor()

		_, err := encryptor.Decrypt("invalid-base64!!!")
		if err == nil {
			t.Fatal("Expected error when decrypting invalid ciphertext")
		}
	})

	t.Run("Decrypt_TooShortCiphertext", func(t *testing.T) {
		encryptor, _ := NewTokenEncryptor()

		// Valid base64 but too short (less than nonce size)
		_, err := encryptor.Decrypt("YWJj") // "abc" in base64
		if err == nil {
			t.Fatal("Expected error when decrypting too short ciphertext")
		}
	})

	t.Run("Encrypt_ProducesDifferentCiphertexts", func(t *testing.T) {
		encryptor, _ := NewTokenEncryptor()

		plaintext := "same-text"
		ciphertext1, _ := encryptor.Encrypt(plaintext)
		ciphertext2, _ := encryptor.Encrypt(plaintext)

		// Due to random nonce, same plaintext should produce different ciphertexts
		if ciphertext1 == ciphertext2 {
			t.Fatal("Same plaintext should produce different ciphertexts due to random nonce")
		}

		// But both should decrypt to the same plaintext
		decrypted1, _ := encryptor.Decrypt(ciphertext1)
		decrypted2, _ := encryptor.Decrypt(ciphertext2)

		if decrypted1 != plaintext || decrypted2 != plaintext {
			t.Fatal("Both ciphertexts should decrypt to the same plaintext")
		}
	})
}

func TestTokenEncryptor_KeyPadding(t *testing.T) {
	t.Run("ShortKey_Padded", func(t *testing.T) {
		os.Setenv("TOKEN_ENCRYPTION_KEY", "short-key")
		defer os.Unsetenv("TOKEN_ENCRYPTION_KEY")

		encryptor, err := NewTokenEncryptor()
		if err != nil {
			t.Fatalf("Failed to create TokenEncryptor with short key: %v", err)
		}

		plaintext := "test-data"
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Failed to encrypt with padded key: %v", err)
		}

		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt with padded key: %v", err)
		}

		if decrypted != plaintext {
			t.Fatalf("Decrypted text mismatch with padded key")
		}
	})

	t.Run("LongKey_Truncated", func(t *testing.T) {
		os.Setenv("TOKEN_ENCRYPTION_KEY", "this-is-a-very-long-key-that-exceeds-32-bytes-and-should-be-truncated")
		defer os.Unsetenv("TOKEN_ENCRYPTION_KEY")

		encryptor, err := NewTokenEncryptor()
		if err != nil {
			t.Fatalf("Failed to create TokenEncryptor with long key: %v", err)
		}

		plaintext := "test-data"
		ciphertext, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Failed to encrypt with truncated key: %v", err)
		}

		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt with truncated key: %v", err)
		}

		if decrypted != plaintext {
			t.Fatalf("Decrypted text mismatch with truncated key")
		}
	})
}
