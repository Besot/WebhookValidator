using System;
using System.Security.Cryptography;
using System.Text;

namespace Besot.WebhookValidator
{
    /// <summary>
    /// Validator for OPay webhook requests that verifies authenticity using RSA signature validation.
    /// </summary>
    public class OpayWebhookValidator : IWebhookValidator
    {
        /// <summary>
        /// Validates an OPay webhook request by verifying its RSA signature.
        /// </summary>
        /// <param name="requestBody">The raw request body content (paramContent from OPay).</param>
        /// <param name="signatureHeader">The signature header from the webhook request in format: signature|timestamp</param>
        /// <param name="opayPublicKey">The OPay public key (in Base64 format) used to verify signatures.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        /// <exception cref="InvalidWebhookRequestException">Thrown when the signature is missing or invalid.</exception>
        /// <remarks>
        /// The signatureHeader should be provided as "signature|timestamp" where:
        /// - signature is the sign field from the OPay webhook request
        /// - timestamp is the timestamp field from the OPay webhook request
        /// </remarks>
        public bool Validate(string requestBody, string signatureHeader, string opayPublicKey)
        {
            if (string.IsNullOrEmpty(requestBody) || string.IsNullOrEmpty(signatureHeader) || string.IsNullOrEmpty(opayPublicKey))
            {
                throw new InvalidWebhookRequestException("opay", "Request body, signature header, and public key must be provided");
            }

            // Parse the signature header to get the signature and timestamp
            string[] parts = signatureHeader.Split("|");
            if (parts.Length != 2)
            {
                return false;
            }

            string signature = parts[0];
            string timestamp = parts[1];

            return VerifySignature(requestBody, timestamp, signature, opayPublicKey);
        }

        /// <summary>
        /// Alternative validation method that takes the individual components directly.
        /// </summary>
        /// <param name="paramContent">The paramContent from the OPay webhook request.</param>
        /// <param name="timestamp">The timestamp from the OPay webhook request.</param>
        /// <param name="signature">The signature from the OPay webhook request.</param>
        /// <param name="opayPublicKey">The OPay public key (in Base64 format) used to verify signatures.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        /// <exception cref="InvalidWebhookRequestException">Thrown when the signature is missing or invalid.</exception>
        public bool Validate(string paramContent, string timestamp, string signature, string opayPublicKey)
        {
            if (string.IsNullOrEmpty(paramContent))
                throw new InvalidWebhookRequestException("opay", "Request body is empty");

            if (string.IsNullOrEmpty(timestamp))
                throw new InvalidWebhookRequestException("opay", "Timestamp is empty");

            if (string.IsNullOrEmpty(signature))
                throw new InvalidWebhookRequestException("opay", "Signature is empty");

            if (string.IsNullOrEmpty(opayPublicKey))
                throw new InvalidWebhookRequestException("opay", "Public key is not configured");

            return VerifySignature(paramContent, timestamp, signature, opayPublicKey);
        }

        /// <summary>
        /// Decrypts the OPay webhook payload using the merchant's private key.
        /// </summary>
        /// <param name="encryptedPayload">The encrypted payload (paramContent from OPay).</param>
        /// <param name="merchantPrivateKey">The merchant's private key (in Base64 format).</param>
        /// <returns>The decrypted payload as a string.</returns>
        public string DecryptPayload(string encryptedPayload, string merchantPrivateKey)
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(merchantPrivateKey), out _);

            var data = Convert.FromBase64String(encryptedPayload);
            var decrypted = rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
            return Encoding.UTF8.GetString(decrypted);
        }

        /// <summary>
        /// Encrypts a payload using OPay's public key.
        /// </summary>
        /// <param name="payload">The payload to encrypt.</param>
        /// <param name="opayPublicKey">OPay's public key (in Base64 format).</param>
        /// <returns>The encrypted payload as a Base64 string.</returns>
        public string EncryptPayload(string payload, string opayPublicKey)
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(opayPublicKey), out _);

            var data = Encoding.UTF8.GetBytes(payload);
            var encrypted = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Generates a signature for outgoing messages to OPay.
        /// </summary>
        /// <param name="paramContent">The content to sign.</param>
        /// <param name="timestamp">The current timestamp.</param>
        /// <param name="merchantPrivateKey">The merchant's private key (in Base64 format).</param>
        /// <returns>The signature as a Base64 string.</returns>
        public string GenerateSignature(string paramContent, string timestamp, string merchantPrivateKey)
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(merchantPrivateKey), out _);

            var toSign = $"{paramContent}{timestamp}";
            var bytes = Encoding.UTF8.GetBytes(toSign);
            var signature = rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signature);
        }

        private bool VerifySignature(string dataBase64, string timestamp, string signatureBase64, string opayPublicKey)
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(opayPublicKey), out _);

            var toVerify = $"{dataBase64}{timestamp}";
            var bytes = Encoding.UTF8.GetBytes(toVerify);
            var signature = Convert.FromBase64String(signatureBase64);
            
            try
            {
                return rsa.VerifyData(bytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch
            {
                return false;
            }
        }
    }
}
