using System;
using System.Security.Cryptography;
using System.Text;
using Besot.WebhookValidator;
using Xunit;

namespace WebhookValidator.Tests
{
    public class OpayWebhookValidatorTests
    {
        private readonly string _testPrivateKey;
        private readonly string _testPublicKey;
        private readonly string _testTimestamp = DateTime.UtcNow.ToString("o");
        private const string TestRequestBody = "{\"reference\":\"OPAY12345\",\"amount\":5000,\"status\":\"successful\"}";
        
        public OpayWebhookValidatorTests()
        {
            // Generate a test RSA key pair for testing
            using var rsa = RSA.Create(2048);
            _testPrivateKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
            _testPublicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
        }

        [Fact]
        public void Validate_WithValidSignature_ReturnsTrue()
        {
            // Arrange
            var validator = new OpayWebhookValidator();
            var validSignature = GenerateOpaySignature(TestRequestBody, _testTimestamp, _testPrivateKey);
            var combinedSignature = $"{validSignature}|{_testTimestamp}";

            // Act
            var result = validator.Validate(TestRequestBody, combinedSignature, _testPublicKey);

            // Assert
            Assert.True(result, "Validation should succeed with a valid signature");
        }

        [Fact]
        public void Validate_WithInvalidSignature_ReturnsFalse()
        {
            // Arrange
            var validator = new OpayWebhookValidator();
            var invalidSignature = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
            var combinedSignature = $"{invalidSignature}|{_testTimestamp}";

            // Act & Assert
            Assert.False(validator.Validate(TestRequestBody, combinedSignature, _testPublicKey),
                "Validation should fail with an invalid signature");
        }

        [Fact]
        public void Validate_WithMissingRequestBody_ThrowsException()
        {
            // Arrange
            var validator = new OpayWebhookValidator();
            var validSignature = GenerateOpaySignature(TestRequestBody, _testTimestamp, _testPrivateKey);
            var combinedSignature = $"{validSignature}|{_testTimestamp}";

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.Validate("", combinedSignature, _testPublicKey));
            
            Assert.Contains("Request body", exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("opay", exception.ProviderName);
        }

        [Fact]
        public void Validate_WithMissingSignature_ThrowsException()
        {
            // Arrange
            var validator = new OpayWebhookValidator();

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.Validate(TestRequestBody, "", _testPublicKey));
            
            Assert.Contains("signature header", exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("opay", exception.ProviderName);
        }

        [Fact]
        public void Validate_IndividualComponents_WithValidSignature_ReturnsTrue()
        {
            // Arrange
            var validator = new OpayWebhookValidator();
            var validSignature = GenerateOpaySignature(TestRequestBody, _testTimestamp, _testPrivateKey);

            // Act
            var result = validator.Validate(TestRequestBody, _testTimestamp, validSignature, _testPublicKey);

            // Assert
            Assert.True(result, "Validation should succeed with valid individual components");
        }

        [Fact]
        public void Validate_IndividualComponents_WithInvalidSignature_ReturnsFalse()
        {
            // Arrange
            var validator = new OpayWebhookValidator();
            var invalidSignature = Convert.ToBase64String(Guid.NewGuid().ToByteArray());

            // Act & Assert
            Assert.False(validator.Validate(TestRequestBody, _testTimestamp, invalidSignature, _testPublicKey),
                "Validation should fail with an invalid signature in individual components");
        }

        [Fact]
        public void Validate_IndividualComponents_WithMissingRequestBody_ThrowsException()
        {
            // Arrange
            var validator = new OpayWebhookValidator();
            var validSignature = GenerateOpaySignature(TestRequestBody, _testTimestamp, _testPrivateKey);

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.Validate("", _testTimestamp, validSignature, _testPublicKey));
            
            Assert.Contains("Request body", exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("opay", exception.ProviderName);
        }

        [Fact]
        public void Validate_IndividualComponents_WithMissingSignature_ThrowsException()
        {
            // Arrange
            var validator = new OpayWebhookValidator();

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.Validate(TestRequestBody, _testTimestamp, "", _testPublicKey));
            
            Assert.Contains("Signature", exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("opay", exception.ProviderName);
        }

        [Fact]
        public void EncryptDecrypt_RoundTrip_WorksCorrectly()
        {
            // Arrange
            var validator = new OpayWebhookValidator();
            var originalPayload = "This is a test payload";

            // Act
            var encrypted = validator.EncryptPayload(originalPayload, _testPublicKey);
            var decrypted = validator.DecryptPayload(encrypted, _testPrivateKey);

            // Assert
            Assert.Equal(originalPayload, decrypted);
        }

        // Helper method to generate a valid Opay signature for testing
        private string GenerateOpaySignature(string payload, string timestamp, string privateKey)
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);

            var toSign = $"{payload}{timestamp}";
            var bytes = Encoding.UTF8.GetBytes(toSign);
            var signature = rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signature);
        }
    }
}
