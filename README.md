# WebhookValidator

A lightweight .NET library for validating webhooks from payment providers like Moniepoint, OPay, and Flutterwave.

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

### Using the Factory with Provider Name

```csharp
using WebhookValidator;

// Create a validator for a specific provider
var validator = WebhookValidatorFactory.Create("moniepoint");
// or
var validator = WebhookValidatorFactory.Create("opay");
// or
var validator = WebhookValidatorFactory.Create("flutterwave");
```

## Features

- Lightweight with no external dependencies
- Supports Moniepoint, OPay, and Flutterwave webhook validation
- Provides both combined and individual component validation methods
- Includes encryption/decryption utilities for OPay
- Exception-based validation for Flutterwave webhooks

## License

MIT
