using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Besot.WebhookValidator
{
    /// <summary>
    /// Validator for Flutterwave webhook requests that verifies the authenticity 
    /// using HMAC-SHA256 signature validation.
    /// </summary>
    public class FlutterwaveWebhookValidator : IWebhookValidator
    {
        /// <summary>
        /// Validates a Flutterwave webhook request by verifying its signature.
        /// </summary>
        /// <param name="requestBody">The raw request body content as string.</param>
        /// <param name="signatureHeader">The signature header from the webhook request (flutterwave-signature).</param>
        /// <param name="secretKey">The webhook secret hash (FLW_SECRET_HASH) provided by Flutterwave.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        /// <exception cref="InvalidWebhookRequestException">Thrown when the signature is missing or invalid.</exception>
        public bool Validate(string requestBody, string signatureHeader, string secretKey)
        {
            if (string.IsNullOrEmpty(requestBody))
                throw new InvalidWebhookRequestException("flutterwave", "Request body is empty");

            if (string.IsNullOrEmpty(signatureHeader))
                throw new InvalidWebhookRequestException("flutterwave", "Signature header is missing");

            if (string.IsNullOrEmpty(secretKey))
                throw new InvalidWebhookRequestException("flutterwave", "Secret key is not configured");

            bool isValid = ValidateSignature(requestBody, signatureHeader, secretKey);
            if (!isValid)
                throw new InvalidWebhookRequestException("flutterwave", "Signature does not match");

            return true;
        }

        /// <summary>
        /// Validates the Flutterwave webhook signature without throwing exceptions.
        /// </summary>
        /// <param name="requestBody">The raw request body content as string.</param>
        /// <param name="signatureHeader">The signature header from the webhook request (flutterwave-signature).</param>
        /// <param name="secretKey">The webhook secret hash (FLW_SECRET_HASH) provided by Flutterwave.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public bool ValidateSignature(string requestBody, string signatureHeader, string secretKey)
        {
            if (string.IsNullOrEmpty(requestBody) || string.IsNullOrEmpty(signatureHeader) || string.IsNullOrEmpty(secretKey))
                return false;

            string computedSignature = ComputeSignature(requestBody, secretKey);
            return signatureHeader.Equals(computedSignature, StringComparison.Ordinal);
        }

        /// <summary>
        /// Computes the HMAC-SHA256 signature of the request body using the secret key.
        /// </summary>
        /// <param name="requestBody">The raw request body content as string.</param>
        /// <param name="secretKey">The webhook secret hash (FLW_SECRET_HASH) provided by Flutterwave.</param>
        /// <returns>The computed signature as a hexadecimal string.</returns>
        public string ComputeSignature(string requestBody, string secretKey)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey));
            byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(requestBody));
            
            // Convert the hash to a hexadecimal string
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        /// <summary>
        /// Parses the payload into a strongly-typed object after validating the signature.
        /// </summary>
        /// <typeparam name="T">The type to deserialize the payload to.</typeparam>
        /// <param name="requestBody">The raw request body content as string.</param>
        /// <param name="signatureHeader">The signature header from the webhook request (flutterwave-signature).</param>
        /// <param name="secretKey">The webhook secret hash (FLW_SECRET_HASH) provided by Flutterwave.</param>
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
                throw new JsonException("Failed to parse Flutterwave webhook payload", ex);
            }
        }

        /// <summary>
        /// Parses the payload into a dynamic object after validating the signature.
        /// </summary>
        /// <param name="requestBody">The raw request body content as string.</param>
        /// <param name="signatureHeader">The signature header from the webhook request (flutterwave-signature).</param>
        /// <param name="secretKey">The webhook secret hash (FLW_SECRET_HASH) provided by Flutterwave.</param>
        /// <returns>The deserialized payload as a JsonElement.</returns>
        /// <exception cref="InvalidWebhookRequestException">Thrown when the signature is missing or invalid.</exception>
        /// <exception cref="JsonException">Thrown when the JSON deserialization fails.</exception>
        public JsonElement ParsePayload(string requestBody, string signatureHeader, string secretKey)
        {
            // First validate the signature
            Validate(requestBody, signatureHeader, secretKey);
            
            // If validation passed, parse the payload
            try
            {
                return JsonSerializer.Deserialize<JsonElement>(requestBody);
            }
            catch (JsonException ex)
            {
                throw new JsonException("Failed to parse Flutterwave webhook payload", ex);
            }
        }
    }
}
