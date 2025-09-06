# WebhookValidator

A lightweight .NET library for validating webhooks from payment providers like Moniepoint, OPay, Flutterwave, and Paystack.

## Installation

```bash
dotnet add package WebhookValidator
```

## Usage

### Moniepoint Webhook Validation

```csharp
using WebhookValidator;

// Method 1: Using the factory
var moniepointValidator = WebhookValidatorFactory.CreateMoniepointValidator();

// Method 2: Direct instantiation
var validator = new MoniepointWebhookValidator();

// Option 1: Combined signature format (webhookId|timestamp|signature)
string requestBody = "{...}"; // Raw webhook payload
string combinedSignature = "webhook-id|timestamp|signature";
string secretKey = "your-moniepoint-webhook-secret-key";

bool isValid = validator.Validate(requestBody, combinedSignature, secretKey);

// Option 2: Individual components
string webhookId = "webhook-id";
string timestamp = "timestamp";
string signature = "signature";

bool isValid = validator.Validate(webhookId, timestamp, requestBody, signature, secretKey);
```

### OPay Webhook Validation

```csharp
using WebhookValidator;

// Method 1: Using the factory
var opayValidator = WebhookValidatorFactory.CreateOpayValidator();

// Method 2: Direct instantiation
var validator = new OpayWebhookValidator();

// Option 1: Combined signature format (signature|timestamp)
string paramContent = "encrypted-payload";
string combinedSignature = "signature|timestamp";
string opayPublicKey = "opay-public-key-base64";

bool isValid = validator.Validate(paramContent, combinedSignature, opayPublicKey);

// Option 2: Individual components
string timestamp = "timestamp";
string signature = "signature";

bool isValid = validator.Validate(paramContent, timestamp, signature, opayPublicKey);

// Decryption (if needed)
string decryptedJson = validator.DecryptPayload(paramContent, "merchant-private-key-base64");
```

### Flutterwave Webhook Validation

```csharp
using WebhookValidator;

// Method 1: Using the factory
var flutterwaveValidator = WebhookValidatorFactory.CreateFlutterwaveValidator();

// Method 2: Direct instantiation
var validator = new FlutterwaveWebhookValidator();

// Validate a webhook
string requestBody = "{...}"; // Raw webhook payload
string signature = "flutterwave-signature-header-value";
string secretHash = "your-flutterwave-secret-hash";

try {
    // Will throw InvalidWebhookSignatureException if the signature is invalid
    bool isValid = validator.Validate(requestBody, signature, secretHash);
    
    // Or use the non-throwing version
    bool isValidSignature = validator.ValidateSignature(requestBody, signature, secretHash);
    
    // Parse the payload after validation
    var payload = validator.ParsePayload<YourFlutterwavePayloadType>(requestBody, signature, secretHash);
    
    // Or parse to a dynamic object
    var dynamicPayload = validator.ParsePayload(requestBody, signature, secretHash);
} catch (InvalidWebhookSignatureException ex) {
    // Handle invalid signature
    Console.WriteLine($"Invalid signature: {ex.Message}");
}
```

### Paystack Webhook Validation

```csharp
using WebhookValidator;

// Method 1: Using the factory without IP validation
var paystackValidator = WebhookValidatorFactory.CreatePaystackValidator();

// Method 2: Using the factory with IP validation enabled
var paystackValidatorWithIpCheck = WebhookValidatorFactory.CreatePaystackValidator(enableIpValidation: true);

// Method 3: Direct instantiation
var validator = new PaystackWebhookValidator(enableIpValidation: false);

// Basic signature validation
string requestBody = "{...}"; // Raw webhook payload
string signature = "x-paystack-signature-header-value";
string secretKey = "your-paystack-secret-key";

try {
    // Will throw InvalidWebhookSignatureException if the signature is invalid
    bool isValid = validator.Validate(requestBody, signature, secretKey);
    
    // With IP validation (if enabled)
    string sourceIp = "52.31.139.75"; // IP address of the webhook sender
    bool isValidWithIp = validator.Validate(requestBody, signature, secretKey, sourceIp);
    
    // Parse the payload after validation
    var payload = validator.ParsePayload<YourPaystackPayloadType>(requestBody, signature, secretKey);
} catch (InvalidWebhookSignatureException ex) {
    // Handle invalid signature or IP
    Console.WriteLine($"Invalid webhook: {ex.Message}");
}
```

### Using the Factory with Provider Name

```csharp
using WebhookValidator;

// Create a validator for a specific provider
var validator = WebhookValidatorFactory.Create("moniepoint");
// or
var validator = WebhookValidatorFactory.Create("opay");
// or
var validator = WebhookValidatorFactory.Create("flutterwave");
// or
var validator = WebhookValidatorFactory.Create("paystack");

// Create a validator with additional options
var options = new WebhookValidatorFactory.WebhookValidatorOptions { EnableIpValidation = true };
var paystackValidator = WebhookValidatorFactory.Create("paystack", options);
```

## Features

- Lightweight with no external dependencies
- Supports Moniepoint, OPay, Flutterwave, and Paystack webhook validation
- Provides both combined and individual component validation methods
- Includes encryption/decryption utilities for OPay
- Exception-based validation for webhooks
- IP address validation for Paystack webhooks

## Provider-Specific Information

### Paystack

Paystack webhooks are validated using HMAC-SHA512 signature validation. The validator checks the provided webhook body against the signature in the `x-paystack-signature` header.

#### IP Validation

Paystack webhooks are sent from specific IP addresses. The validator can optionally check if the source IP is in the list of Paystack's whitelisted IPs:

- 52.31.139.75
- 52.49.173.169
- 52.214.14.220

#### Validation Process

1. Extract the raw JSON body of the webhook event
2. Compute a HMAC SHA512 hash of the raw body using the Paystack secret key
3. Compare it against the value of the `x-paystack-signature` header
4. If IP validation is enabled, check if the source IP is in the whitelist

#### Error Messages

The validator will throw an `InvalidWebhookRequestException` with detailed messages for various error scenarios:

- Missing raw body: "Webhook raw body is missing or empty."
- Missing signature: "Signature header is missing."
- Invalid signature: "Invalid Paystack webhook signature."
- Invalid source IP: "Invalid Paystack source IP."

## License

MIT
