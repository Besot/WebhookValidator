using System;
using System.Security.Cryptography;
using System.Text;

namespace Besot.WebhookValidator
{
    /// <summary>
    /// Validator for Moniepoint webhook requests that verifies the authenticity 
    /// using HMAC-SHA256 signature validation.
    /// </summary>
    public class MoniepointWebhookValidator : IWebhookValidator
    {
        /// <summary>
        /// Validates a Moniepoint webhook request by verifying its signature.
        /// </summary>
        /// <param name="requestBody">The raw request body content as string.</param>
        /// <param name="signatureHeader">The signature header from the webhook request (moniepoint-webhook-signature).</param>
        /// <param name="secretKey">The webhook secret key provided by Moniepoint.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        /// <exception cref="InvalidWebhookRequestException">Thrown when the signature is missing or invalid.</exception>
        /// <remarks>
        /// This method requires additional headers from the original request:
        /// - webhookId: The webhook ID (moniepoint-webhook-id header)
        /// - timestamp: The timestamp (moniepoint-webhook-timestamp header)
        /// These values should be included in the signatureHeader parameter as a pipe-delimited string: webhookId|timestamp|signature
        /// </remarks>
        public bool Validate(string requestBody, string signatureHeader, string secretKey)
        {
            if (string.IsNullOrEmpty(requestBody) || string.IsNullOrEmpty(signatureHeader) || string.IsNullOrEmpty(secretKey))
            {
                throw new InvalidWebhookRequestException("moniepoint", "Request body, signature header, and secret key must be provided");
            }

            // Parse the signature header to get the webhook ID, timestamp, and signature
            string[] parts = signatureHeader.Split("|");
            if (parts.Length != 3)
            {
                return false;
            }

            string webhookId = parts[0];
            string timestamp = parts[1];
            string signature = parts[2];

            return IsPayloadSignatureValid(webhookId, timestamp, requestBody, signature, secretKey);
        }

        /// <summary>
        /// Alternative validation method that takes the individual components directly.
        /// </summary>
        /// <param name="webhookId">The Moniepoint webhook ID header value.</param>
        /// <param name="timestamp">The Moniepoint webhook timestamp header value.</param>
        /// <param name="requestBody">The raw request body content as string.</param>
        /// <param name="signature">The Moniepoint webhook signature header value.</param>
        /// <param name="secretKey">The webhook secret key provided by Moniepoint.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        /// <exception cref="InvalidWebhookRequestException">Thrown when the signature is missing or invalid.</exception>
        public static bool Validate(string webhookId, string timestamp, string requestBody, string signature, string secretKey)
        {
            if (string.IsNullOrEmpty(webhookId))
                throw new InvalidWebhookRequestException("moniepoint", "Webhook ID is empty");

            if (string.IsNullOrEmpty(timestamp))
                throw new InvalidWebhookRequestException("moniepoint", "Timestamp is empty");

            if (string.IsNullOrEmpty(requestBody))
                throw new InvalidWebhookRequestException("moniepoint", "Request body is empty");

            if (string.IsNullOrEmpty(signature))
                throw new InvalidWebhookRequestException("moniepoint", "Signature is empty");

            if (string.IsNullOrEmpty(secretKey))
                throw new InvalidWebhookRequestException("moniepoint", "Secret key is not configured");

            return IsPayloadSignatureValid(webhookId, timestamp, requestBody, signature, secretKey);
        }

        private static bool IsPayloadSignatureValid(string webhookId, string timestamp, string requestBody, string signature, string secretKey)
        {
            var data = $"{webhookId}__{timestamp}__{requestBody}";

            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey));
            var computedSignature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(data)));

            return signature == computedSignature;
        }
    }
}
