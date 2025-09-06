using System;
using System.Security.Cryptography;
using System.Text;
using Besot.WebhookValidator;
using Xunit;

namespace WebhookValidator.Tests
{
    public class MoniepointWebhookValidatorTests
    {
        private const string TestSecretKey = "test-secret-key-12345";
        private const string TestWebhookId = "webhook-123456789";
        private readonly string _testTimestamp = DateTime.UtcNow.ToString("o");
        private const string TestRequestBody = "{\"reference\":\"MP12345\",\"amount\":5000,\"status\":\"successful\"}";

        [Fact]
        public void Validate_WithValidSignature_ReturnsTrue()
        {
            // Arrange
            var validator = new MoniepointWebhookValidator();
            var validSignature = GenerateMoniepointSignature(TestWebhookId, _testTimestamp, TestRequestBody, TestSecretKey);
            var combinedSignature = $"{TestWebhookId}|{_testTimestamp}|{validSignature}";

            // Act
            var result = validator.Validate(TestRequestBody, combinedSignature, TestSecretKey);

            // Assert
            Assert.True(result, "Validation should succeed with a valid signature");
        }

        [Fact]
        public void Validate_WithInvalidSignature_ReturnsFalse()
        {
            // Arrange
            var validator = new MoniepointWebhookValidator();
            var invalidSignature = "invalid-signature-value";
            var combinedSignature = $"{TestWebhookId}|{_testTimestamp}|{invalidSignature}";

            // Act & Assert
            Assert.False(validator.Validate(TestRequestBody, combinedSignature, TestSecretKey),
                "Validation should fail with an invalid signature");
        }

        [Fact]
        public void Validate_WithMissingRequestBody_ThrowsException()
        {
            // Arrange
            var validator = new MoniepointWebhookValidator();
            var validSignature = GenerateMoniepointSignature(TestWebhookId, _testTimestamp, TestRequestBody, TestSecretKey);
            var combinedSignature = $"{TestWebhookId}|{_testTimestamp}|{validSignature}";

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.Validate("", combinedSignature, TestSecretKey));
            
            Assert.Contains("Request body", exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("moniepoint", exception.ProviderName);
        }

        [Fact]
        public void Validate_WithMissingSignature_ThrowsException()
        {
            // Arrange
            var validator = new MoniepointWebhookValidator();

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.Validate(TestRequestBody, "", TestSecretKey));
            
            Assert.Contains("signature header", exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("moniepoint", exception.ProviderName);
        }

        [Fact]
        public void StaticValidate_WithValidSignature_ReturnsTrue()
        {
            // Arrange
            var validSignature = GenerateMoniepointSignature(TestWebhookId, _testTimestamp, TestRequestBody, TestSecretKey);

            // Act
            var result = MoniepointWebhookValidator.Validate(TestWebhookId, _testTimestamp, TestRequestBody, validSignature, TestSecretKey);

            // Assert
            Assert.True(result, "Static validation should succeed with a valid signature");
        }

        [Fact]
        public void StaticValidate_WithInvalidSignature_ReturnsFalse()
        {
            // Arrange
            var invalidSignature = "invalid-signature-value";

            // Act & Assert
            Assert.False(MoniepointWebhookValidator.Validate(TestWebhookId, _testTimestamp, TestRequestBody, invalidSignature, TestSecretKey),
                "Static validation should fail with an invalid signature");
        }

        [Fact]
        public void StaticValidate_WithMissingRequestBody_ThrowsException()
        {
            // Arrange
            var validSignature = GenerateMoniepointSignature(TestWebhookId, _testTimestamp, TestRequestBody, TestSecretKey);

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                MoniepointWebhookValidator.Validate(TestWebhookId, _testTimestamp, "", validSignature, TestSecretKey));
            
            Assert.Contains("Request body", exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("moniepoint", exception.ProviderName);
        }

        [Fact]
        public void StaticValidate_WithMissingSignature_ThrowsException()
        {
            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                MoniepointWebhookValidator.Validate(TestWebhookId, _testTimestamp, TestRequestBody, "", TestSecretKey));
            
            Assert.Contains("Signature", exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("moniepoint", exception.ProviderName);
        }

        // Helper method to generate a valid Moniepoint signature for testing
        private string GenerateMoniepointSignature(string webhookId, string timestamp, string requestBody, string secretKey)
        {
            var data = $"{webhookId}__{timestamp}__{requestBody}";
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey));
            return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(data)));
        }
    }
}
