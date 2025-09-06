using System;

namespace Besot.WebhookValidator
{
    /// <summary>
    /// Exception thrown when a webhook signature is invalid or missing.
    /// </summary>
    [Serializable]
    public class InvalidWebhookRequestException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidWebhookRequestException"/> class.
        /// </summary>
        public InvalidWebhookRequestException() : base("Invalid webhook signature")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidWebhookRequestException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public InvalidWebhookRequestException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidWebhookRequestException"/> class with a specified error message
        /// and a reference to the inner exception that is the cause of this exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public InvalidWebhookRequestException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidWebhookRequestException"/> class with the provider name.
        /// </summary>
        /// <param name="providerName">The name of the payment provider whose signature validation failed.</param>
        public InvalidWebhookRequestException(string providerName, string reason) 
            : base($"Invalid webhook signature for {providerName}: {reason}")
        {
            ProviderName = providerName;
            Reason = reason;
        }

        /// <summary>
        /// Gets the name of the payment provider whose signature validation failed.
        /// </summary>
        public string? ProviderName { get; }

        /// <summary>
        /// Gets the specific reason for the signature validation failure.
        /// </summary>
        public string? Reason { get; }
    }
}
