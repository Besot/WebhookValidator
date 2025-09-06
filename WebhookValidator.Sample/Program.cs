using System;
using System.Text.Json;
using Besot.WebhookValidator;

namespace WebhookValidator.Sample
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("WebhookValidator Sample Application");
            Console.WriteLine("===================================");
            
            // Sample Moniepoint validation
            Console.WriteLine("\nMoniepoint Webhook Validation Example:");
            
            // Creating a Moniepoint validator
            var moniepointValidator = WebhookValidatorFactory.CreateMoniepointValidator();
            
            string moniepointRequestBody = "{\"reference\":\"MP123456\",\"amount\":5000}";
            string webhookId = "webhook-123";
            string timestamp = DateTime.UtcNow.ToString("o");
            string secretKey = "moniepoint-webhook-secret-key";
            
            // Generate a valid signature for the sample (this would normally come from the webhook request)
            string validSignature = GenerateMoniepointSignature(webhookId, timestamp, moniepointRequestBody, secretKey);
            string invalidSignature = "invalid-signature";
            
            // Test with valid signature
            string combinedValidHeader = $"{webhookId}|{timestamp}|{validSignature}";
            bool isValidMoniepoint = moniepointValidator.Validate(moniepointRequestBody, combinedValidHeader, secretKey);
            bool isValidMoniepointStatic = MoniepointWebhookValidator.Validate(webhookId, timestamp, moniepointRequestBody, validSignature, secretKey);
            Console.WriteLine($"Valid Moniepoint signature test: {isValidMoniepoint}");
            Console.WriteLine($"Valid Moniepoint signature test (static method): {isValidMoniepointStatic}");
            
            // Test with invalid signature
            string combinedInvalidHeader = $"{webhookId}|{timestamp}|{invalidSignature}";
            bool isInvalidMoniepoint = moniepointValidator.Validate(moniepointRequestBody, combinedInvalidHeader, secretKey);
            Console.WriteLine($"Invalid Moniepoint signature test: {isInvalidMoniepoint}");

            // Sample OPay validation
            Console.WriteLine("\nOPay Webhook Validation Example:");
            Console.WriteLine("(Note: Full RSA validation would require actual OPay keys)");
            
            // Creating an OPay validator
            var opayValidator = WebhookValidatorFactory.CreateOpayValidator();
            
            // Sample Flutterwave validation
            Console.WriteLine("\nFlutterwave Webhook Validation Example:");
            
            // Creating a Flutterwave validator
            var flutterwaveValidator = WebhookValidatorFactory.CreateFlutterwaveValidator();
            
            string flutterwaveRequestBody = "{\"event\":\"charge.completed\",\"data\":{\"id\":1234567890}}";
            string flwSecretHash = "flutterwave-secret-hash";
            
            // Generate a valid signature for the sample (this would normally come from the webhook request)
            string flwValidSignature = GenerateFlutterwaveSignature(flutterwaveRequestBody, flwSecretHash);
            string flwInvalidSignature = "invalid-signature";
            
            // Test with valid signature
            bool isValidFlutterwave = flutterwaveValidator.ValidateSignature(flutterwaveRequestBody, flwValidSignature, flwSecretHash);
            Console.WriteLine($"Valid Flutterwave signature test: {isValidFlutterwave}");
            
            // Test with invalid signature
            bool isInvalidFlutterwave = flutterwaveValidator.ValidateSignature(flutterwaveRequestBody, flwInvalidSignature, flwSecretHash);
            Console.WriteLine($"Invalid Flutterwave signature test: {isInvalidFlutterwave}");
            
            // Test exception throwing with invalid signature
            Console.WriteLine("\nTesting exception handling with invalid signature:");
            try
            {
                flutterwaveValidator.Validate(flutterwaveRequestBody, flwInvalidSignature, flwSecretHash);
                Console.WriteLine("This line shouldn't be reached!");
            }
            catch (InvalidWebhookRequestException ex)
            {
                Console.WriteLine($"Caught expected exception: {ex.Message}");
            }
            
            // Test payload parsing
            Console.WriteLine("\nTesting payload parsing:");
            try
            {
                var payload = flutterwaveValidator.ParsePayload<JsonDocument>(flutterwaveRequestBody, flwValidSignature, flwSecretHash);
                Console.WriteLine($"Successfully parsed payload: {payload.RootElement.ToString()}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error parsing payload: {ex.Message}");
            }

            Console.WriteLine("\nFactory example:");
            var genericValidator = WebhookValidatorFactory.Create("moniepoint");
            Console.WriteLine($"Created validator of type: {genericValidator.GetType().Name}");
            
            var flwValidator = WebhookValidatorFactory.Create("flutterwave");
            Console.WriteLine($"Created validator of type: {flwValidator.GetType().Name}");
        }
        
        // Helper method to generate a valid Moniepoint signature for testing
        private static string GenerateMoniepointSignature(string webhookId, string timestamp, string requestBody, string secretKey)
        {
            var data = $"{webhookId}__{timestamp}__{requestBody}";
            
            using var hmac = new System.Security.Cryptography.HMACSHA256(
                System.Text.Encoding.UTF8.GetBytes(secretKey));
            
            return Convert.ToBase64String(
                hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data)));
        }
        
        // Helper method to generate a valid Flutterwave signature for testing
        private static string GenerateFlutterwaveSignature(string requestBody, string secretHash)
        {
            using var hmac = new System.Security.Cryptography.HMACSHA256(
                System.Text.Encoding.UTF8.GetBytes(secretHash));
            
            byte[] hash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(requestBody));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
    }
}
