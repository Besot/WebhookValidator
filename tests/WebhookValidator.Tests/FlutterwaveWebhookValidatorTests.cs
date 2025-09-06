using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Besot.WebhookValidator;
using Xunit;

namespace WebhookValidator.Tests
{
    public class FlutterwaveWebhookValidatorTests
    {
        private const string TestSecretHash = "test-flw-secret-hash-12345";
        private const string TestRequestBody = "{\"event\":\"charge.completed\",\"data\":{\"id\":1234567890,\"tx_ref\":\"FLW-TXN-123\",\"amount\":5000,\"currency\":\"NGN\",\"status\":\"successful\"}}";

        [Fact]
        public void Validate_WithValidSignature_ReturnsTrue()
        {
            // Arrange
            var validator = new FlutterwaveWebhookValidator();
            var validSignature = ComputeFlutterwaveSignature(TestRequestBody, TestSecretHash);

            // Act
            var result = validator.Validate(TestRequestBody, validSignature, TestSecretHash);

            // Assert
            Assert.True(result, "Validation should succeed with a valid signature");
        }

        [Fact]
        public void Validate_WithInvalidSignature_ThrowsException()
        {
            // Arrange
            var validator = new FlutterwaveWebhookValidator();
            var invalidSignature = "invalid-signature-value";

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.Validate(TestRequestBody, invalidSignature, TestSecretHash));
            
            Assert.Contains("Signature does not match", exception.Message);
            Assert.Equal("flutterwave", exception.ProviderName);
        }

        [Fact]
        public void ValidateSignature_WithInvalidSignature_ReturnsFalse()
        {
            // Arrange
            var validator = new FlutterwaveWebhookValidator();
            var invalidSignature = "invalid-signature-value";

            // Act
            var result = validator.ValidateSignature(TestRequestBody, invalidSignature, TestSecretHash);

            // Assert
            Assert.False(result, "ValidateSignature should return false with an invalid signature");
        }

        [Fact]
        public void Validate_WithMissingRequestBody_ThrowsException()
        {
            // Arrange
            var validator = new FlutterwaveWebhookValidator();
            var validSignature = ComputeFlutterwaveSignature(TestRequestBody, TestSecretHash);

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.Validate("", validSignature, TestSecretHash));
            
            Assert.Contains("Request body", exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("flutterwave", exception.ProviderName);
        }

        [Fact]
        public void Validate_WithMissingSignature_ThrowsException()
        {
            // Arrange
            var validator = new FlutterwaveWebhookValidator();

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.Validate(TestRequestBody, "", TestSecretHash));
            
            Assert.Contains("Signature header", exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("flutterwave", exception.ProviderName);
        }

        [Fact]
        public void ComputeSignature_ReturnsExpectedValue()
        {
            // Arrange
            var validator = new FlutterwaveWebhookValidator();
            
            // Act
            var signature = validator.ComputeSignature(TestRequestBody, TestSecretHash);
            
            // Assert
            var expectedSignature = ComputeFlutterwaveSignature(TestRequestBody, TestSecretHash);
            Assert.Equal(expectedSignature, signature);
        }

        [Fact]
        public void ParsePayload_WithValidSignature_ReturnsDeserializedObject()
        {
            // Arrange
            var validator = new FlutterwaveWebhookValidator();
            var validSignature = ComputeFlutterwaveSignature(TestRequestBody, TestSecretHash);
            
            // Act
            var result = validator.ParsePayload<JsonDocument>(TestRequestBody, validSignature, TestSecretHash);
            
            // Assert
            Assert.NotNull(result);
            var jsonElement = result.RootElement;
            Assert.Equal("charge.completed", jsonElement.GetProperty("event").GetString());
            Assert.Equal(1234567890, jsonElement.GetProperty("data").GetProperty("id").GetInt32());
        }

        [Fact]
        public void ParsePayload_WithInvalidSignature_ThrowsException()
        {
            // Arrange
            var validator = new FlutterwaveWebhookValidator();
            var invalidSignature = "invalid-signature-value";
            
            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.ParsePayload<JsonDocument>(TestRequestBody, invalidSignature, TestSecretHash));
            
            Assert.Contains("Signature does not match", exception.Message);
            Assert.Equal("flutterwave", exception.ProviderName);
        }

        [Fact]
        public void ParsePayload_JsonElement_WithValidSignature_ReturnsDeserializedObject()
        {
            // Arrange
            var validator = new FlutterwaveWebhookValidator();
            var validSignature = ComputeFlutterwaveSignature(TestRequestBody, TestSecretHash);
            
            // Act
            var result = validator.ParsePayload(TestRequestBody, validSignature, TestSecretHash);
            
            // Assert
            Assert.Equal("charge.completed", result.GetProperty("event").GetString());
            Assert.Equal(1234567890, result.GetProperty("data").GetProperty("id").GetInt32());
        }

        // Helper method to compute a Flutterwave signature for testing
        private string ComputeFlutterwaveSignature(string requestBody, string secretHash)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretHash));
            byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(requestBody));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
    }
}
