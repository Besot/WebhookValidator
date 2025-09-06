using System;

namespace Besot.WebhookValidator
{
    /// <summary>
    /// Factory class to create webhook validators for different payment providers.
    /// </summary>
    public static class WebhookValidatorFactory
    {
        /// <summary>
        /// Creates a Moniepoint webhook validator instance.
        /// </summary>
        /// <returns>An instance of MoniepointWebhookValidator.</returns>
        public static MoniepointWebhookValidator CreateMoniepointValidator()
        {
            return new MoniepointWebhookValidator();
        }

        /// <summary>
        /// Creates an OPay webhook validator instance.
        /// </summary>
        /// <returns>An instance of OpayWebhookValidator.</returns>
        public static OpayWebhookValidator CreateOpayValidator()
        {
            return new OpayWebhookValidator();
        }
        
        /// <summary>
        /// Creates a Flutterwave webhook validator instance.
        /// </summary>
        /// <returns>An instance of FlutterwaveWebhookValidator.</returns>
        public static FlutterwaveWebhookValidator CreateFlutterwaveValidator()
        {
            return new FlutterwaveWebhookValidator();
        }

        /// <summary>
        /// Creates a Paystack webhook validator instance.
        /// </summary>
        /// <param name="enableIpValidation">Whether to enable IP validation.</param>
        /// <returns>An instance of PaystackWebhookValidator.</returns>
        public static PaystackWebhookValidator CreatePaystackValidator(bool enableIpValidation = false)
        {
            return new PaystackWebhookValidator(enableIpValidation);
        }

        /// <summary>
        /// Creates a webhook validator for the specified payment provider.
        /// </summary>
        /// <param name="providerName">The name of the payment provider ("moniepoint", "opay", "flutterwave", or "paystack").</param>
        /// <returns>An instance of the appropriate webhook validator.</returns>
        /// <exception cref="ArgumentException">Thrown when an unsupported provider name is specified.</exception>
        public static IWebhookValidator Create(string providerName)
        {
            return providerName.ToLowerInvariant() switch
            {
                "moniepoint" => new MoniepointWebhookValidator(),
                "opay" => new OpayWebhookValidator(),
                "flutterwave" => new FlutterwaveWebhookValidator(),
                "paystack" => new PaystackWebhookValidator(),
                _ => throw new ArgumentException($"Unsupported payment provider: {providerName}", nameof(providerName))
            };
        }
        
        /// <summary>
        /// Creates a webhook validator for the specified payment provider with additional options.
        /// </summary>
        /// <param name="providerName">The name of the payment provider.</param>
        /// <param name="options">Additional options for configuring the validator.</param>
        /// <returns>An instance of the appropriate webhook validator.</returns>
        /// <exception cref="ArgumentException">Thrown when an unsupported provider name is specified.</exception>
        public static IWebhookValidator Create(string providerName, WebhookValidatorOptions options)
        {
            if (providerName.Equals("paystack", StringComparison.OrdinalIgnoreCase) && 
                options != null && options.EnableIpValidation)
            {
                return new PaystackWebhookValidator(true);
            }
            
            return Create(providerName);
        }
        
        /// <summary>
        /// Options for configuring webhook validators.
        /// </summary>
        public class WebhookValidatorOptions
        {
            /// <summary>
            /// Gets or sets whether IP validation is enabled.
            /// </summary>
            public bool EnableIpValidation { get; set; }
        }
    }
}
