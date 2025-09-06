using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Besot.WebhookValidator
{
    /// <summary>
    /// Validator for Paystack webhook requests that verifies the authenticity 
    /// using HMAC-SHA512 signature validation and optional IP whitelisting.
    /// </summary>
    public class PaystackWebhookValidator : IWebhookValidator
    {
        // Whitelisted Paystack IPs
        private static readonly string[] WhitelistedIps = new[] 
        {
            "52.31.139.75",
            "52.49.173.169",
            "52.214.14.220"
        };
        
        private bool _enableIpValidation;

        /// <summary>
        /// Initializes a new instance of the <see cref="PaystackWebhookValidator"/> class.
        /// </summary>
        /// <param name="enableIpValidation">Whether to enable IP address validation.</param>
        public PaystackWebhookValidator(bool enableIpValidation = false)
        {
            _enableIpValidation = enableIpValidation;
        }

        /// <summary>
        /// Validates a Paystack webhook request by verifying its signature.
        /// </summary>
        /// <param name="requestBody">The raw request body content as string.</param>
        /// <param name="signatureHeader">The signature header from the webhook request (x-paystack-signature).</param>
        /// <param name="secretKey">The webhook secret key provided by Paystack.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        /// <exception cref="InvalidWebhookRequestException">Thrown when the signature is missing or invalid.</exception>
        public bool Validate(string requestBody, string signatureHeader, string secretKey)
        {
            if (string.IsNullOrEmpty(requestBody))
                throw new InvalidWebhookRequestException("paystack", "Webhook raw body is missing or empty.");

            if (string.IsNullOrEmpty(signatureHeader))
                throw new InvalidWebhookRequestException("paystack", "Signature header is missing.");

            if (string.IsNullOrEmpty(secretKey))
                throw new InvalidWebhookRequestException("paystack", "Secret key is not configured");

            bool isValid = ValidateSignature(requestBody, signatureHeader, secretKey);
            if (!isValid)
                throw new InvalidWebhookRequestException("paystack", "Invalid Paystack webhook signature.");

            return true;
        }

        /// <summary>
        /// Validates a Paystack webhook request by verifying its signature and optionally the source IP.
        /// </summary>
        /// <param name="requestBody">The raw request body content as string.</param>
        /// <param name="signatureHeader">The signature header from the webhook request (x-paystack-signature).</param>
        /// <param name="secretKey">The webhook secret key provided by Paystack.</param>
        /// <param name="sourceIp">The IP address of the webhook request sender.</param>
        /// <returns>True if the validation passes, false otherwise.</returns>
        /// <exception cref="InvalidWebhookRequestException">Thrown when validation fails.</exception>
        public bool Validate(string requestBody, string signatureHeader, string secretKey, string sourceIp)
        {
            // First validate the signature
            Validate(requestBody, signatureHeader, secretKey);
            
            // If IP validation is enabled, verify the source IP
            if (_enableIpValidation && !string.IsNullOrEmpty(sourceIp))
            {
                if (!IsValidSourceIp(sourceIp))
                    throw new InvalidWebhookRequestException("paystack", "Invalid Paystack source IP.");
            }
            
            return true;
        }

        /// <summary>
        /// Validates the Paystack webhook signature without throwing exceptions.
        /// </summary>
        /// <param name="requestBody">The raw request body content as string.</param>
        /// <param name="signatureHeader">The signature header from the webhook request (x-paystack-signature).</param>
        /// <param name="secretKey">The webhook secret key provided by Paystack.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public bool ValidateSignature(string requestBody, string signatureHeader, string secretKey)
        {
            if (string.IsNullOrEmpty(requestBody) || string.IsNullOrEmpty(signatureHeader) || string.IsNullOrEmpty(secretKey))
                return false;

            string computedSignature = ComputeSignature(requestBody, secretKey);
            return signatureHeader.Equals(computedSignature, StringComparison.Ordinal);
        }

        /// <summary>
        /// Computes the HMAC-SHA512 signature of the request body using the secret key.
        /// </summary>
        /// <param name="requestBody">The raw request body content as string.</param>
        /// <param name="secretKey">The webhook secret key provided by Paystack.</param>
        /// <returns>The computed signature as a hexadecimal string.</returns>
        public string ComputeSignature(string requestBody, string secretKey)
        {
            using var hmac = new HMACSHA512(Encoding.UTF8.GetBytes(secretKey));
            byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(requestBody));
            
            // Convert the hash to a hexadecimal string
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        /// <summary>
        /// Validates whether the source IP is in the list of whitelisted Paystack IPs.
        /// </summary>
        /// <param name="sourceIp">The IP address to validate.</param>
        /// <returns>True if the IP is valid, false otherwise.</returns>
        public bool IsValidSourceIp(string sourceIp)
        {
            return WhitelistedIps.Contains(sourceIp);
        }

        /// <summary>
        /// Parses the payload into a strongly-typed object after validating the signature.
        /// </summary>
        /// <typeparam name="T">The type to deserialize the payload to.</typeparam>
        /// <param name="requestBody">The raw request body content as string.</param>
        /// <param name="signatureHeader">The signature header from the webhook request (x-paystack-signature).</param>
        /// <param name="secretKey">The webhook secret key provided by Paystack.</param>
        /// <returns>The deserialized payload object.</returns>
        /// <exception cref="InvalidWebhookRequestException">Thrown when the signature is missing or invalid.</exception>
        /// <exception cref="JsonException">Thrown when the JSON deserialization fails.</exception>
        public T ParsePayload<T>(string requestBody, string signatureHeader, string secretKey)
        {
            // First validate the signature
            Validate(requestBody, signatureHeader, secretKey);
            
            // If validation passed, parse the payload
            try
            {
                return JsonSerializer.Deserialize<T>(requestBody) ?? 
                    throw new JsonException("Failed to deserialize webhook payload");
            }
            catch (JsonException ex)
            {
                throw new JsonException("Failed to parse Paystack webhook payload", ex);
            }
        }
    }
}
