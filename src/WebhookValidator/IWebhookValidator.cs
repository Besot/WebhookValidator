using System;

namespace Besot.WebhookValidator
{
    /// <summary>
    /// Interface for webhook validators used to verify the authenticity of incoming webhooks.
    /// </summary>
    public interface IWebhookValidator
    {
        /// <summary>
        /// Validates a webhook request by verifying its signature against the provided secret key.
        /// </summary>
        /// <param name="requestBody">The raw request body content as string.</param>
        /// <param name="signatureHeader">The signature header value from the webhook request.</param>
        /// <param name="secretKey">The secret key used for signature verification.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        bool Validate(string requestBody, string signatureHeader, string secretKey);
    }
}
