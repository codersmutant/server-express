<?php
/**
 * Template for Express PayPal Buttons
 * 
 * This template is served via an iframe to Website A for Express Checkout
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    // If accessed directly, return minimal HTML with error
    if (empty($_GET['rest_route'])) {
        echo '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>Direct access not allowed.</body></html>';
        exit;
    }
}

// Get parameters
$amount = isset($amount) ? $amount : (isset($_GET['amount']) ? sanitize_text_field($_GET['amount']) : '0.00');
$currency = isset($currency) ? $currency : (isset($_GET['currency']) ? sanitize_text_field($_GET['currency']) : 'USD');
$api_key = isset($api_key) ? $api_key : (isset($_GET['api_key']) ? sanitize_text_field($_GET['api_key']) : '');
$client_id = isset($client_id) ? $client_id : '';
$environment = isset($environment) ? $environment : 'sandbox';
$callback_url = isset($callback_url) ? $callback_url : (isset($_GET['callback_url']) ? sanitize_text_field($_GET['callback_url']) : '');
$site_url = isset($site_url) ? $site_url : (isset($_GET['site_url']) ? sanitize_text_field($_GET['site_url']) : '');
$needs_shipping = isset($needs_shipping) ? $needs_shipping : (isset($_GET['needs_shipping']) && $_GET['needs_shipping'] === 'yes');
$context = isset($_GET['context']) ? sanitize_text_field($_GET['context']) : 'default';

// Format amount for display
$formatted_amount = number_format((float)$amount, 2, '.', ',');

// Set DOCTYPE to HTML5
?><!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PayPal Express Checkout</title>
    
    <!-- Add styling -->
    <style>
        /* Basic reset */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen-Sans, Ubuntu, Cantarell, 'Helvetica Neue', sans-serif;
            line-height: 1.4;
            color: #333;
            padding: 0;
            background-color: transparent;
        }
        
        /* Container */
        .container {
            width: 100%;
            position: relative;
        }
        
        /* PayPal buttons container */
        #paypal-express-button-container {
            width: 100%;
            min-height: 45px;
        }
        
        /* Messages */
        #paypal-message, 
        #paypal-error,
        #paypal-success {
            margin: 8px 0;
            padding: 8px;
            border-radius: 4px;
            font-size: 14px;
            display: none;
        }
        
        #paypal-message {
            background-color: #f8f9fa;
            border: 1px solid #d6d8db;
            color: #1e2125;
        }
        
        #paypal-error {
            background-color: #f8d7da;
            border: 1px solid #f5c2c7;
            color: #842029;
        }
        
        #paypal-success {
            background-color: #d1e7dd;
            border: 1px solid #badbcc;
            color: #0f5132;
        }
        
        /* Processing overlay */
        #paypal-processing {
            display: none;
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(255, 255, 255, 0.8);
            flex-direction: column;
            justify-content: center;
            align-items: center;
            z-index: 10;
        }
        
        .spinner {
            width: 25px;
            height: 25px;
            border: 2px solid #f3f3f3;
            border-top: 2px solid #3498db;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: 8px;
        }
        
        .processing-text {
            font-size: 14px;
            color: #333;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        /* Shipping options section */
        #shipping-options-container {
            margin-top: 15px;
            display: none;
        }
        
        #shipping-options-title {
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .shipping-option {
            margin: 5px 0;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.2s;
            display: flex;
            justify-content: space-between;
        }
        
        .shipping-option:hover {
            background-color: #f5f5f5;
        }
        
        .shipping-option.selected {
            background-color: #e7f4ff;
            border-color: #0070ba;
        }
        
        .shipping-option-label {
            flex: 1;
        }
        
        .shipping-option-price {
            font-weight: bold;
            margin-left: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- PayPal buttons container -->
        <div id="paypal-express-button-container"></div>
        
        <!-- Shipping options container -->
        <div id="shipping-options-container">
            <div id="shipping-options-title"><?php _e('Choose shipping method:', 'woo-paypal-proxy-server'); ?></div>
            <div id="shipping-options-list"></div>
        </div>
        
        <!-- Message containers -->
        <div id="paypal-message"></div>
        <div id="paypal-error"></div>
        <div id="paypal-success"></div>
        
        <!-- Processing overlay -->
        <div id="paypal-processing">
            <div class="spinner"></div>
            <div class="processing-text"><?php _e('Processing...', 'woo-paypal-proxy-server'); ?></div>
        </div>
    </div>
    
    <!-- Add hidden fields for JS -->
    <input type="hidden" id="api-key" value="<?php echo esc_attr($api_key); ?>">
    <input type="hidden" id="amount" value="<?php echo esc_attr($amount); ?>">
    <input type="hidden" id="currency" value="<?php echo esc_attr($currency); ?>">
    <input type="hidden" id="site-url" value="<?php echo esc_attr($site_url); ?>">
    <input type="hidden" id="callback-url" value="<?php echo esc_attr($callback_url); ?>">
    <input type="hidden" id="needs-shipping" value="<?php echo $needs_shipping ? 'yes' : 'no'; ?>">
    <input type="hidden" id="context" value="<?php echo esc_attr($context); ?>">
    
    <?php if (!empty($client_id)) : ?>
    <!-- PayPal SDK -->
    <script src="https://www.paypal.com/sdk/js?client-id=<?php echo esc_attr($client_id); ?>&currency=<?php echo esc_attr($currency); ?>&intent=capture&commit=true<?php echo $needs_shipping ? '&components=buttons,funding-eligibility,hosted-fields' : '&components=buttons'; ?>"></script>
    <?php endif; ?>
    
    <!-- Express Checkout script -->
    <script>
        // Debug logging
        function log(message, data) {
            console.log('[PayPal Express]', message, data !== undefined ? data : '');
        }
        
        // Store parent window origin if possible
        var parentOrigin = '*';
        var siteUrl = document.getElementById('site-url').value;
        var context = document.getElementById('context').value || 'default';
        var iframeId = 'paypal-express-iframe-' + context;
        var orderData = {
            wcOrderId: null,
            paypalOrderId: null,
            amount: document.getElementById('amount').value || '0',
            currency: document.getElementById('currency').value || 'USD',
            apiKey: document.getElementById('api-key').value || '',
            callbackUrl: document.getElementById('callback-url').value || '',
            needsShipping: document.getElementById('needs-shipping').value === 'yes',
            shippingAddress: null,
            shippingOptions: [],
            selectedShippingOption: null
        };
        
        if (siteUrl) {
            try {
                // Decode if it's base64 encoded
                if (siteUrl.indexOf('%') === -1 && /^[A-Za-z0-9+/=]+$/.test(siteUrl)) {
                    siteUrl = atob(siteUrl);
                } else {
                    siteUrl = decodeURIComponent(siteUrl);
                }
                
                var siteUrlObj = new URL(siteUrl);
                parentOrigin = siteUrlObj.origin;
            } catch (e) {
                log('Error parsing site URL:', e);
            }
        }
        
        /**
         * Show error message
         */
        function showError(message) {
            var errorContainer = document.getElementById('paypal-error');
            if (errorContainer) {
                errorContainer.textContent = message;
                errorContainer.style.display = 'block';
                
                document.getElementById('paypal-message').style.display = 'none';
                document.getElementById('paypal-success').style.display = 'none';
            }
            
            // Resize iframe to fit content
            resizeIframe();
        }
        
        /**
         * Show success message
         */
        function showSuccess(message) {
            var successContainer = document.getElementById('paypal-success');
            if (successContainer) {
                successContainer.textContent = message;
                successContainer.style.display = 'block';
                
                document.getElementById('paypal-message').style.display = 'none';
                document.getElementById('paypal-error').style.display = 'none';
            }
            
            // Resize iframe to fit content
            resizeIframe();
        }
        
        /**
         * Show general message
         */
        function showMessage(message) {
            var messageContainer = document.getElementById('paypal-message');
            if (messageContainer) {
                messageContainer.textContent = message;
                messageContainer.style.display = 'block';
                
                document.getElementById('paypal-error').style.display = 'none';
                document.getElementById('paypal-success').style.display = 'none';
            }
            
            // Resize iframe to fit content
            resizeIframe();
        }
        
        /**
         * Show processing indicator
         */
        function showProcessing() {
            var processingContainer = document.getElementById('paypal-processing');
            if (processingContainer) {
                processingContainer.style.display = 'flex';
            }
        }
        
        /**
         * Hide processing indicator
         */
        function hideProcessing() {
            var processingContainer = document.getElementById('paypal-processing');
            if (processingContainer) {
                processingContainer.style.display = 'none';
            }
        }
        
        /**
         * Send message to parent window
         */
        function sendMessageToParent(message) {
            // Add source identifier and iframe ID
            message.source = 'paypal-express-proxy';
            message.iframeId = iframeId;
            
            log('Sending message to parent:', message);
            
            // Send message
            window.parent.postMessage(message, parentOrigin);
        }
        
        /**
         * Display shipping options
         */
        function displayShippingOptions(options) {
            if (!options || options.length === 0) {
                log('No shipping options to display');
                document.getElementById('shipping-options-container').style.display = 'none';
                return;
            }
            
            var optionsContainer = document.getElementById('shipping-options-list');
            optionsContainer.innerHTML = '';
            
            log('Displaying ' + options.length + ' shipping options');
            
            // Store options
            orderData.shippingOptions = options;
            
            // Build option elements
            options.forEach(function(option) {
                var optionElement = document.createElement('div');
                optionElement.className = 'shipping-option';
                optionElement.setAttribute('data-id', option.id);
                
                // Format cost
                var formattedCost = new Intl.NumberFormat(undefined, {
                    style: 'currency',
                    currency: orderData.currency
                }).format(option.cost);
                
                optionElement.innerHTML = 
                    '<div class="shipping-option-label">' + option.label + '</div>' +
                    '<div class="shipping-option-price">' + formattedCost + '</div>';
                
                // Add click handler
                optionElement.addEventListener('click', function() {
                    selectShippingOption(option.id);
                });
                
                optionsContainer.appendChild(optionElement);
            });
            
            // Show container
            document.getElementById('shipping-options-container').style.display = 'block';
            
            // Resize iframe to fit content
            resizeIframe();
        }
        
        /**
         * Select shipping option
         */
        function selectShippingOption(optionId) {
            log('Shipping option selected:', optionId);
            
            // Store selected option
            orderData.selectedShippingOption = optionId;
            
            // Update UI
            var options = document.querySelectorAll('.shipping-option');
            for (var i = 0; i < options.length; i++) {
                options[i].classList.remove('selected');
                if (options[i].getAttribute('data-id') === optionId) {
                    options[i].classList.add('selected');
                }
            }
            
            // Notify parent window
            sendMessageToParent({
                action: 'shipping_option_selected',
                selectedOption: optionId
            });
        }
        
        /**
         * Resize iframe to fit content
         */
        function resizeIframe() {
            // Calculate new height (add some padding)
            var height = document.body.scrollHeight + 20;
            
            // Send resize message to parent
            sendMessageToParent({
                action: 'resize_iframe',
                height: height
            });
            
            log('Resized iframe to height ' + height);
        }
        
        /**
         * Create PayPal order
         */
        function createPayPalOrder(data) {
            log('Creating PayPal order with data:', data);
            
            // Store order data
            orderData.wcOrderId = data.order_id;
            orderData.paypalOrderId = data.paypal_order_id;
            
            log('Stored order IDs. WC: ' + orderData.wcOrderId + ', PayPal: ' + orderData.paypalOrderId);
            
            return orderData.paypalOrderId;
        }
        
        // Initialize PayPal buttons
function initPayPalButtons() {
    log('Initializing PayPal Express Checkout buttons');
    
    // Check if PayPal SDK is available
    if (typeof paypal === 'undefined') {
        log('PayPal SDK not loaded');
        showError('PayPal SDK could not be loaded. Please try again later.');
        return;
    }
    
    // Notify parent window that buttons are loaded
    sendMessageToParent({
        action: 'button_loaded'
    });
    
    // Render PayPal buttons
    paypal.Buttons({
        // Style the buttons
        style: {
            layout: 'horizontal',  // horizontal | vertical
            color: 'gold',         // gold | blue | silver | black
            shape: 'rect',         // pill | rect
            label: 'paypal',       // pay | checkout | paypal | buynow
            tagline: false
        },
        
        // Create order
        createOrder: function(data, actions) {
            log('PayPal button clicked');
            
            // Notify parent window that button was clicked
            sendMessageToParent({
                action: 'button_clicked'
            });
            
            // Wait for order data from parent
            return new Promise(function(resolve, reject) {
                log('Waiting for order data from parent window...');
                
                // Create message handler
                var messageHandler = function(event) {
                    log('Received message from parent:', event.data);
                    
                    // Check if message is for us
                    var data = event.data;
                    if (!data || !data.action || data.source !== 'woocommerce-client') {
                        return;
                    }
                    
                    // Handle create_paypal_order action
                    if (data.action === 'create_paypal_order') {
                        log('Received order data from parent');
                        
                        // Remove event listener
                        window.removeEventListener('message', messageHandler);
                        
                        // Create PayPal order with the data
                        resolve(data.paypal_order_id);
                    }
                };
                
                // Add message listener
                window.addEventListener('message', messageHandler);
                
                // Set timeout for order creation
                setTimeout(function() {
                    log('Timeout waiting for order data');
                    window.removeEventListener('message', messageHandler);
                    reject(new Error('Timeout waiting for order data'));
                }, 30000);
            });
        },
        
        // Handle shipping address
onShippingChange: function(data, actions) {
    // This only applies if needsShipping is true
    if (!orderData.needsShipping) {
        return actions.resolve();
    }
    
    log('Shipping address changed:', data.shipping_address);
    
    // Store address
    orderData.shippingAddress = data.shipping_address;
    
    // Notify parent window to get shipping options
    sendMessageToParent({
        action: 'shipping_options_needed',
        address: data.shipping_address
    });
    
    // Return a promise that resolves when parent sends shipping options
    return new Promise(function(resolve, reject) {
        var messageHandler = function(event) {
            // Check if message is for us
            var msgData = event.data;
            if (!msgData || !msgData.action || msgData.source !== 'woocommerce-client') {
                return;
            }
            
            if (msgData.action === 'shipping_options_available') {
                log('Received shipping options from parent:', msgData.shipping_options);
                
                // Remove event listener
                window.removeEventListener('message', messageHandler);
                
                // Format shipping options for PayPal
                if (msgData.shipping_options && msgData.shipping_options.length > 0) {
                    var paypalShippingOptions = [];
                    
                    msgData.shipping_options.forEach(function(option) {
                        paypalShippingOptions.push({
                            id: option.id,
                            label: option.label,
                            type: 'SHIPPING',
                            selected: false,
                            amount: {
                                value: option.cost,
                                currency_code: orderData.currency
                            }
                        });
                    });
                    
                    // Set first option as selected
                    if (paypalShippingOptions.length > 0) {
                        paypalShippingOptions[0].selected = true;
                    }
                    
                    log('Returning shipping options to PayPal:', paypalShippingOptions);
                    
                    // CRITICAL: Return shipping options to PayPal in their expected format
                    resolve({ shippingOptions: paypalShippingOptions });
                } else {
                    // Just resolve normally if no options
                    resolve();
                }
                
                // Also display shipping options in our own UI
                displayShippingOptions(msgData.shipping_options);
            } else if (msgData.action === 'shipping_options_error') {
                // Error handling...
            }
        };
        
        // Add message listener
        window.addEventListener('message', messageHandler);
    });
},
        
        // Handle shipping option selection in PayPal's UI
        onShippingOptionChange: function(data, actions) {
            log('PayPal shipping option changed:', data);
            
            var selectedOptionId = data.selectedShippingOption.id;
            
            // Update our UI
            selectShippingOption(selectedOptionId);
            
            // Notify parent of selection
            sendMessageToParent({
                action: 'shipping_option_selected',
                selectedOption: selectedOptionId
            });
            
            // Return promise
            return new Promise(function(resolve, reject) {
                var messageHandler = function(event) {
                    var msgData = event.data;
                    if (!msgData || !msgData.action || msgData.source !== 'woocommerce-client') {
                        return;
                    }
                    
                    if (msgData.action === 'shipping_method_updated') {
                        window.removeEventListener('message', messageHandler);
                        resolve();
                    } else if (msgData.action === 'shipping_method_error') {
                        window.removeEventListener('message', messageHandler);
                        showError(msgData.message || 'Failed to update shipping method');
                        reject();
                    }
                };
                
                window.addEventListener('message', messageHandler);
                
                // Set timeout
                setTimeout(function() {
                    window.removeEventListener('message', messageHandler);
                    resolve(); // Resolve anyway to not block UI
                }, 5000);
            });
        },
        
        // On approval
        onApprove: function(data, actions) {
            log('Payment approved by user:', data);
            
            // Show processing message
            showProcessing();
            
            // Notify parent window
            sendMessageToParent({
                action: 'payment_approved',
                payload: {
                    orderID: data.orderID,
                    wcOrderId: orderData.wcOrderId,
                    paypalData: data
                }
            });
            
            // Show success message
            hideProcessing();
            showSuccess('Payment successful! Finalizing your order...');
            
            //return actions.order.capture();
            
            return actions.order.capture().then(function(captureData) {
                log('PayPal SDK capture complete (informational only):', captureData);
                // We still rely on the parent window handler to complete the order
            });
        },
        
        // On cancel
        onCancel: function(data) {
            log('Payment cancelled by user:', data);
            
            // Notify parent window
            sendMessageToParent({
                action: 'payment_cancelled',
                payload: data
            });
            
            showMessage('Payment cancelled. You can try again when you\'re ready.');
        },
        
        // On error
        onError: function(err) {
            log('PayPal error:', err);
            
            // Notify parent window
            sendMessageToParent({
                action: 'payment_error',
                error: {
                    message: err.message || 'An error occurred'
                }
            });
            
            showError('PayPal error: ' + (err.message || 'An error occurred'));
        }
    }).render('#paypal-express-button-container');
    
    // Initial resize
    setTimeout(resizeIframe, 500);
}
        
        // Initialize when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initPayPalButtons);
        } else {
            initPayPalButtons();
        }
    </script>
</body>
</html>