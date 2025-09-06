using System;
using System.Security.Cryptography;
using System.Text;
using Besot.WebhookValidator;
using Xunit;

namespace WebhookValidator.Tests
{
    public class PaystackWebhookValidatorTests
    {
        private const string TestSecretKey = "sk_test_paystack-secret-key-12345";
        private const string TestRequestBody = "{\"event\":\"charge.success\",\"data\":{\"id\":1234567890,\"reference\":\"PSK-TXN-123\",\"amount\":5000,\"currency\":\"NGN\",\"status\":\"success\"}}";
        private const string ValidIp1 = "52.31.139.75";
        private const string ValidIp2 = "52.49.173.169";
        private const string ValidIp3 = "52.214.14.220";
        private const string InvalidIp = "192.168.1.1";

        // Helper method to compute a valid signature for testing
        private string ComputePaystackSignature(string payload, string secretKey)
        {
            using var hmac = new HMACSHA512(Encoding.UTF8.GetBytes(secretKey));
            byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        [Fact]
        public void Validate_WithValidSignature_ReturnsTrue()
        {
            // Arrange
            var validator = new PaystackWebhookValidator();
            var validSignature = ComputePaystackSignature(TestRequestBody, TestSecretKey);

            // Act
            var result = validator.Validate(TestRequestBody, validSignature, TestSecretKey);

            // Assert
            Assert.True(result, "Validation should succeed with a valid signature");
        }

        [Fact]
        public void Validate_WithValidSignatureAndValidIp_ReturnsTrue()
        {
            // Arrange
            var validator = new PaystackWebhookValidator(enableIpValidation: true);
            var validSignature = ComputePaystackSignature(TestRequestBody, TestSecretKey);

            // Act
            var result = validator.Validate(TestRequestBody, validSignature, TestSecretKey, ValidIp1);

            // Assert
            Assert.True(result, "Validation should succeed with a valid signature and IP");
        }

        [Fact]
        public void Validate_WithMissingRequestBody_ThrowsException()
        {
            // Arrange
            var validator = new PaystackWebhookValidator();
            var validSignature = ComputePaystackSignature(TestRequestBody, TestSecretKey);

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.Validate("", validSignature, TestSecretKey));
            
            Assert.Equal("Invalid webhook signature for paystack: Webhook raw body is missing or empty.", exception.Message);
            Assert.Equal("paystack", exception.ProviderName);
        }

        [Fact]
        public void Validate_WithMissingSignature_ThrowsException()
        {
            // Arrange
            var validator = new PaystackWebhookValidator();

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.Validate(TestRequestBody, "", TestSecretKey));
            
            Assert.Equal("Invalid webhook signature for paystack: Signature header is missing.", exception.Message);
            Assert.Equal("paystack", exception.ProviderName);
        }

        [Fact]
        public void Validate_WithInvalidSignature_ThrowsException()
        {
            // Arrange
            var validator = new PaystackWebhookValidator();
            var invalidSignature = "invalid-signature-value";

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.Validate(TestRequestBody, invalidSignature, TestSecretKey));
            
            Assert.Equal("Invalid webhook signature for paystack: Invalid Paystack webhook signature.", exception.Message);
            Assert.Equal("paystack", exception.ProviderName);
        }

        [Fact]
        public void Validate_WithInvalidIp_ThrowsException()
        {
            // Arrange
            var validator = new PaystackWebhookValidator(enableIpValidation: true);
            var validSignature = ComputePaystackSignature(TestRequestBody, TestSecretKey);

            // Act & Assert
            var exception = Assert.Throws<InvalidWebhookRequestException>(() => 
                validator.Validate(TestRequestBody, validSignature, TestSecretKey, InvalidIp));
            
            Assert.Equal("Invalid webhook signature for paystack: Invalid Paystack source IP.", exception.Message);
            Assert.Equal("paystack", exception.ProviderName);
        }

        [Theory]
        [InlineData(ValidIp1)]
        [InlineData(ValidIp2)]
        [InlineData(ValidIp3)]
        public void IsValidSourceIp_WithValidIp_ReturnsTrue(string validIp)
        {
            // Arrange
            var validator = new PaystackWebhookValidator();

            // Act
            var result = validator.IsValidSourceIp(validIp);

            // Assert
            Assert.True(result, $"IP {validIp} should be valid");
        }

        [Fact]
        public void IsValidSourceIp_WithInvalidIp_ReturnsFalse()
        {
            // Arrange
            var validator = new PaystackWebhookValidator();

            // Act
            var result = validator.IsValidSourceIp(InvalidIp);

            // Assert
            Assert.False(result, $"IP {InvalidIp} should be invalid");
        }

        [Fact]
        public void ComputeSignature_ReturnsExpectedValue()
        {
            // Arrange
            var validator = new PaystackWebhookValidator();
            
            // Act
            var signature = validator.ComputeSignature(TestRequestBody, TestSecretKey);
            
            // Assert
            var expectedSignature = ComputePaystackSignature(TestRequestBody, TestSecretKey);
            Assert.Equal(expectedSignature, signature);
        }
    }
}
